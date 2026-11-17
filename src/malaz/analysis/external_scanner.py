"""Generic, configurable external scanner integration.

This module is the honest answer to "bind in our EDR's CLI" (e.g. Cynet) or any
other command-line scanner for which we do not (and must not) hard-code flags.
We provide the *mechanism*; the vendor-specific binary path and arguments are
supplied by configuration (typically by the customer's IT, taken from the
vendor's documentation). Nothing here invents vendor flags.

Each entry in ``config.EXTERNAL_SCANNERS`` is a dict::

    {
        "name":           "Cynet",                 # label shown in the report
        "binary":         r"C:\\...\\cynet.exe",   # or a name resolvable on PATH
        "args":           ["scan", "{file}"],      # "{file}" is replaced by the path
        "threat_rc":      1,                       # return code meaning "threat"
        "clean_rc":       0,                       # return code meaning "clean"
        "threat_markers": ["threat", "malware"],   # output substrings -> threat
        "clean_markers":  ["clean", "no threat"],  # output substrings -> clean
        "timeout":        90,                      # seconds
    }

Security (see docs/SECURITY_MODEL.md):
* The command is run with an argument list and ``shell=False``; the file path
  replaces the dedicated ``{file}`` *token* (one argv element), so an
  attacker-controlled filename cannot inject shell syntax.
* ``binary`` is resolved from the configured path or PATH only.
* A hard ``timeout`` bounds every call.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .. import config
from ..core.toolpath import which_absolute
from ..procio import (
    decode_tool_output,
    run_tool,
    strip_scan_target,
    tool_output_truncated,
)

log = logging.getLogger(__name__)

_FILE_TOKEN = "{file}"


@dataclass
class ExternalScanResult:
    name: str = ""
    scanned: bool = False
    threat_found: bool = False
    returncode: int | None = None
    detail: str = ""
    skipped_reason: str | None = None

    @property
    def clean(self) -> bool:
        return self.scanned and not self.threat_found


@dataclass
class _Spec:
    name: str
    binary: str
    args: list[str] = field(default_factory=list)
    threat_rc: int | None = None
    clean_rc: int | None = 0
    threat_markers: tuple[str, ...] = ()
    clean_markers: tuple[str, ...] = ()
    timeout: int = 90


def _spec_from_dict(cfg: dict) -> _Spec | None:
    if not isinstance(cfg, dict):
        return None
    binary = str(cfg.get("binary", "")).strip()
    if not binary:
        return None
    name = str(cfg.get("name") or binary).strip() or binary
    args = [str(a) for a in list(cfg.get("args") or [])]
    if _is_batch_wrapper(binary):
        for token in args:
            if _FILE_TOKEN in token and token != _FILE_TOKEN:
                log.warning(
                    "Externer Batch-Scanner %s abgelehnt: {file} darf bei "
                    ".bat/.cmd nur ein eigenes Argument sein, nicht Teil von %r "
                    "(cmd-Injection-Risiko)",
                    name,
                    token,
                )
                return None
    timeout = _opt_int(cfg.get("timeout"))
    return _Spec(
        name=name,
        binary=binary,
        args=args,
        threat_rc=_opt_int(cfg.get("threat_rc")),
        clean_rc=_opt_int(cfg.get("clean_rc")),
        threat_markers=tuple(str(m).lower() for m in (cfg.get("threat_markers") or ())),
        clean_markers=tuple(str(m).lower() for m in (cfg.get("clean_markers") or ())),
        # 0/negative/invalid values make no sense for subprocess timeouts and
        # would otherwise be silently replaced by a default via `or`-fallback.
        timeout=timeout if timeout and timeout > 0 else 90,
    )


def _opt_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# Windows startet ``.bat``/``.cmd`` über cmd.exe; cmd parst die fertige
# Kommandozeile erneut. Für solche Wrapper ist nur ein ALLEIN stehendes
# ``{file}``-Token zulässig, und auch dann darf der Dateiname keine
# cmd-Metazeichen enthalten (SEC-024).
_BATCH_SUFFIXES = (".bat", ".cmd")
_CMD_METACHARACTERS = frozenset('&|<>^%!"()')


def _is_batch_wrapper(binary: str) -> bool:
    expanded = os.path.expandvars(binary).strip().strip('"').strip("'")
    return Path(expanded).suffix.lower() in _BATCH_SUFFIXES


def _unsafe_for_batch(target: str) -> bool:
    return any(
        char in _CMD_METACHARACTERS or ord(char) < 32
        for char in target
    )


class ExternalScanner:
    """Drives one configured external scanner."""

    def __init__(self, cfg: dict):
        self._spec = _spec_from_dict(cfg)
        self._resolved: Path | None = self._locate() if self._spec else None

    @property
    def name(self) -> str:
        return self._spec.name if self._spec else "?"

    @property
    def available(self) -> bool:
        return self._spec is not None and self._resolved is not None

    def _locate(self) -> Path | None:
        if self._spec is None:
            return None
        expanded = os.path.expandvars(self._spec.binary)
        path = Path(expanded)
        if path.is_file():
            return path
        # Maybe it is a bare name resolvable on PATH.
        found = which_absolute(expanded)
        return Path(found) if found else None

    def scan_path(self, path: Path | str) -> ExternalScanResult:
        name = self.name
        if not self.available:
            return ExternalScanResult(
                name=name,
                skipped_reason=f"{name}: Binary nicht gefunden/konfiguriert",
            )
        # Same contract as the other external engines: an absolute path, so the
        # scanner never resolves a relative target against its own cwd.
        target = Path(path).resolve()
        if not target.is_file():
            return ExternalScanResult(
                name=name, skipped_reason=f"{name}: Datei nicht auf Datenträger"
            )
        return self._run(target)

    def _build_args(self, target: str) -> list[str]:
        if self._spec is None or self._resolved is None:  # guarded in _run
            return []
        args = [str(self._resolved)]
        for token in self._spec.args:
            # Substring replacement keeps "{file}" usable inside a flag value
            # (e.g. "--file={file}"); the result stays ONE argv element, so an
            # attacker-controlled path can never inject shell syntax.
            args.append(token.replace(_FILE_TOKEN, target))
        return args

    def _run(self, target: Path) -> ExternalScanResult:
        if self._spec is None or self._resolved is None:
            return ExternalScanResult(
                name=self.name,
                skipped_reason=f"{self.name}: Binary nicht gefunden/konfiguriert",
            )
        spec = self._spec
        is_batch = _is_batch_wrapper(spec.binary) or _is_batch_wrapper(
            str(self._resolved)
        )
        if is_batch:
            if any(
                _FILE_TOKEN in token and token != _FILE_TOKEN
                for token in spec.args
            ):
                return ExternalScanResult(
                    name=spec.name,
                    skipped_reason=(
                        f"{spec.name}: {{file}} ist bei einem Batch-Wrapper "
                        "kein eigenes Argument — Konfiguration abgelehnt "
                        "(cmd-Injection-Risiko, SEC-024)."
                    ),
                )
            if _unsafe_for_batch(str(target)):
                return ExternalScanResult(
                    name=spec.name,
                    skipped_reason=(
                        f"{spec.name}: Dateiname enthält cmd-Metazeichen — "
                        "Batch-Wrapper wird nicht gestartet (Argument-Injection-"
                        "Risiko, SEC-024)."
                    ),
                )
        args = self._build_args(str(target))
        try:
            proc = run_tool(args, timeout=spec.timeout)
        except subprocess.TimeoutExpired:
            return ExternalScanResult(
                name=spec.name,
                skipped_reason=f"{spec.name}: Scan abgebrochen (Timeout > {spec.timeout}s)",
            )
        except FileNotFoundError:
            return ExternalScanResult(
                name=spec.name, skipped_reason=f"{spec.name}: Binary nicht gefunden"
            )
        except Exception as exc:
            return ExternalScanResult(
                name=spec.name,
                skipped_reason=f"{spec.name}: {type(exc).__name__}: {exc}",
            )

        rc, raw_out, raw_err = proc
        output = _decode(raw_out) + _decode(raw_err)
        # Marker matching AND the report excerpt run on the output with the
        # scanned path removed — the excerpt lands in the report, and the
        # path is user/attacker controlled.
        analysis_text = strip_scan_target(output, str(target))
        excerpt = analysis_text.strip()[: config.MAX_STRING_CAPTURE]

        # SEC-023: a cut-off output is a prefix. The verdict markers may sit
        # beyond the cap, and the visible part can look clean (or contain a
        # half line). No marker/return-code verdict is derived from it: the
        # result stays INCONCLUSIVE ("not checked"), never CLEAN or THREAT.
        if tool_output_truncated(proc):
            log.warning(
                "Extern %s: Ausgabe an der Obergrenze abgeschnitten (rc=%s) — "
                "Scan nicht aussagekräftig, output=%r",
                spec.name,
                rc,
                output[:2000],
            )
            return ExternalScanResult(
                name=spec.name,
                scanned=False,
                returncode=rc,
                skipped_reason=(
                    f"{spec.name}: Ausgabe wurde an der Ausgabe-Obergrenze "
                    "abgeschnitten — Scan nicht aussagekräftig und NICHT als "
                    "'sauber' zu werten"
                ),
                detail=excerpt,
            )

        low = analysis_text.lower()

        # Return codes are explicit and win over text. Between the marker
        # lists a CLEAN marker wins over a threat SUBSTRING: "No threats found"
        # contains "threat", and the old threat-first order turned a clean tool
        # result into EXT_*_THREAT CRITICAL/50 (BUG-033).
        rc_threat = spec.threat_rc is not None and rc == spec.threat_rc
        rc_clean = spec.clean_rc is not None and rc == spec.clean_rc
        marker_threat = any(m in low for m in spec.threat_markers)
        marker_clean = any(m in low for m in spec.clean_markers)
        if rc_threat:
            threat, clean = True, False
        elif rc_clean:
            threat, clean = False, True
        else:
            clean = marker_clean
            threat = marker_threat and not marker_clean

        # Die vollstaendige Ausgabe ins Protokoll — wie bei windows_av
        # ("logged verbatim so a wrong verdict can be diagnosed").
        #
        # GEMESSEN: dieser Logger existierte, wurde aber NIRGENDS aufgerufen.
        # Die Rohausgabe eines externen Scanners stand damit ausschliesslich im
        # Befund-Detail. Solange das Detail gekuerzt wird, waere sie danach
        # NIRGENDS mehr — der Nutzer koennte ein falsches Urteil nicht mehr
        # nachvollziehen. Deshalb steht sie hier, VOR den Rueckgaben.
        log.info(
            "Extern %s rc=%s threat=%s clean=%s output=%r",
            spec.name,
            rc,
            threat,
            clean,
            output[:2000],
        )

        if threat:
            return ExternalScanResult(
                name=spec.name,
                scanned=True,
                threat_found=True,
                returncode=rc,
                detail=f"{spec.name}: Bedrohung erkannt (rc={rc}). {excerpt}",
            )
        if clean and not threat:
            return ExternalScanResult(
                name=spec.name,
                scanned=True,
                threat_found=False,
                returncode=rc,
                detail=f"{spec.name}: keine Bedrohung (rc={rc}). {excerpt}",
            )
        return ExternalScanResult(
            name=spec.name,
            scanned=False,
            returncode=rc,
            skipped_reason=f"{spec.name}: nicht aussagekräftig (rc={rc})",
            detail=excerpt,
        )


    @property
    def configured(self) -> bool:
        """True when the config entry was well-formed (binary present)."""
        return self._spec is not None


def build_scanners() -> list[ExternalScanner]:
    """Instantiate one scanner per configured entry (empty list if none)."""
    out: list[ExternalScanner] = []
    for cfg in getattr(config, "EXTERNAL_SCANNERS", ()) or ():
        scanner = ExternalScanner(cfg)
        if scanner.configured:  # ignore malformed entries silently
            out.append(scanner)
    return out


def _decode(raw: bytes | None) -> str:
    return decode_tool_output(raw)
