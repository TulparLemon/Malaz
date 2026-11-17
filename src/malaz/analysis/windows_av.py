"""Local Windows Defender integration via ``MpCmdRun.exe``.

Scans a file with the built-in Windows Defender command-line tool using a
custom scan (``-Scan -ScanType 3 -File <path>``).

The verdict is derived from **both** the process return code and the scan
output text, so that an active Defender is never reported as "skipped" just
because a particular build returns an unusual code:

* return code ``2``  -> threat found  (fed into scoring as a CRITICAL anchor),
  unless the output shows the scan itself failed (e.g. "CmdTool: Failed with
  hr = 0x80508023"); a failed scan also exits 2 but is reported inconclusive
* return code ``0``  -> clean (unless the output explicitly names a threat)
* Defender's structured result token ("Scanning <path> found N threats.") ->
  threat for N >= 1, clean for "found no threats"; it is read with the echoed
  path removed, so an attacker-controlled file name cannot vote
* other output text saying "found no threats"/"keine Bedrohungen" -> clean, but
  only while the return code does not report a threat
* output text naming a detected threat -> threat
* only when neither a known code nor a clear output verdict is present
  (binary missing, timeout, service error) -> inconclusive, skipped gracefully

Remediation policy (``config.AV_DISABLE_REMEDIATION``):
* Default (``False``) — Defender MAY act on a detected threat (clean /
  quarantine / remove). This is the protective choice: if Defender stops a
  virus, that is a good outcome. The tool detects the remediation action from
  the scan output and reports it ("erkannt und unter Quarantäne gestellt").
* ``True`` — pure analysis: ``-DisableRemediation`` is passed so the sample is
  preserved on disk (e.g. for further forensic review).

Note: real-time protection (RTP) acts independently of this on-demand scan and
may quarantine a malicious file the moment it touches disk regardless of the
remediation flag chosen here.

Security notes (see docs/SECURITY_MODEL.md):
* The subprocess is started with an **argument list** and ``shell=False``; the
  file path is passed as a single literal ``argv`` element to ``CreateProcess``.
  No shell ever interprets the path, so command injection is not possible even
  for attacker-controlled file names.
* ``MpCmdRun.exe`` is resolved only from fixed, internal install locations —
  never from payload data.
* A hard timeout bounds the blocking subprocess so a hung scan cannot stall a
  worker thread.
"""

from __future__ import annotations

import glob
import logging
import os
import re
import subprocess
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..procio import (
    decode_tool_output,
    run_tool,
    safe_temp_suffix,
    strip_scan_target,
    tool_output_truncated,
)

log = logging.getLogger(__name__)

# Output phrases used to derive a verdict when the return code alone is
# ambiguous. MpCmdRun is localised, so both English and German are covered.
_CLEAN_PHRASES = (
    "found no threats",
    "no threats found",
    "no malware found",
    "keine bedrohungen",
    "keine bedrohung",
)
_THREAT_PHRASES = (
    "threats detected",
    "threat detected",
    "threat found",
    "threats found",
    "found threat",
    "malware detected",
    "malware found",
    "virus detected",
    "virus found",
    "bedrohung gefunden",
    "bedrohungen gefunden",
    "bedrohung erkannt",
    "bedrohungen erkannt",
    "viren erkannt",
    "virus erkannt",
    "trojaner erkannt",
    "schadsoftware erkannt",
)

# Defender's structured result token: current builds report
# "Scanning <path> found 1 threats." (or "found no threats.") and then
# remediate, exiting with RETURNCODE 0 (not 2). The plain phrases above cannot
# match "found 1 threats" — a count sits between "found" and "threats" — so the
# token is parsed structurally instead of by substring.
#
# Dieser Token ist die ZWEITE Verteidigungslinie gegen den Pfad-Echo. Der
# gescannte Pfad ist angreiferkontrolliert und kommt in der OEM-Codepage
# zurueck (Zeichen, die sie nicht kennt, werden zu "?", z. B. U+2713) und
# moeglicherweise als 8.3-Kurzname. Der Token steht am ENDE einer solchen
# Zeile, hinter dem Echo — deshalb ist der LETZTE Token einer Zeile Defender's
# eigenes Ergebnis, waehrend alles davor (das Echo, samt einem Dateinamen wie
# "found no threats") keines ist.
#
# Die ERSTE Linie ist ``procio.strip_scan_target``: es entfernt den Basisnamen
# in zwei Formen — roh und mit "?" fuer jedes Nicht-ASCII-Zeichen. Eine
# frueher hier stehende Behauptung, der Echo sei grundsaetzlich nicht zu
# entfernen, war zu streng formuliert und ist mit dieser Erweiterung hinfaellig
# (gemessen: eine Datei "threat detected \u2713.pdf" kippte das Urteil, weil
# der Echo stehenblieb).
_STRUCTURED_RESULT_RE = re.compile(
    r"\bfound\s+(?P<count>no|[1-9]\d*)\s+(?:threats?|viruses?|malware)\b",
    re.IGNORECASE,
)


def _structured_verdict(output: str) -> str | None:
    """Verdict from Defender's structured result token, ``None`` without one.

    The last token wins: the path echo precedes the result, so a file named
    "found 1 threats.pdf" cannot outvote the token Defender wrote at the end.
    """
    last = None
    for match in _STRUCTURED_RESULT_RE.finditer(output):
        last = match
    if last is None:
        return None
    return "clean" if last.group("count").lower() == "no" else "threat"


def _strip_result_echo(output: str) -> str:
    """Drop the echoed scan path from lines that carry a result token.

    Everything in front of the last result token on such a line IS the path
    echo — attacker-controlled text. The phrase heuristics (failure,
    remediation, disabled) read the returned text, so a file named
    "removed.pdf" or "scan aborted.pdf" cannot fake a signal any more.
    """
    lines = []
    for line in output.splitlines():
        matches = list(_STRUCTURED_RESULT_RE.finditer(line))
        lines.append(line[matches[-1].start() :] if matches else line)
    return "\n".join(lines)


def _merge_verdicts(
    raw_structured: str | None, stripped_verdict: str | None
) -> str | None:
    """Combine the raw result token with the verdict from the stripped text.

    The structured token is read from the UNSTRIPPED output because Defender
    writes its result at the end of the line, behind the path echo. When
    :func:`strip_scan_target` removes an echo that is byte-identical to a file
    name such as ``found 1 threats``, that raw token is the only surviving
    evidence of the detection — it must win over the now-verdict-less text.

    A threat from either side wins; stripping must never turn a detection
    into clean. Phrase heuristics are deliberately NOT run on the raw text:
    a file named ``threat detected.pdf`` is data, not a verdict.
    """
    if "threat" in (raw_structured, stripped_verdict):
        return "threat"
    if "clean" in (raw_structured, stripped_verdict):
        return "clean"
    return None


def _verdict_from_output(output: str) -> str | None:
    """Return ``"clean"``, ``"threat"`` or ``None`` based on the scan output.

    Defender's structured result token decides first :func:`_structured_verdict`.

    Otherwise clean phrases are checked before threat phrases: they are explicit
    negations ("found no threats", "keine Bedrohungen") that never appear in a
    genuine threat report, and this ordering avoids the substring pitfall where
    "keine Bedrohungen gefunden" also contains the threat fragment
    "Bedrohungen gefunden".
    """
    structured = _structured_verdict(output)
    if structured is not None:
        return structured
    text = output.lower()
    if any(p in text for p in _CLEAN_PHRASES):
        return "clean"
    if any(p in text for p in _THREAT_PHRASES):
        return "threat"
    return None


# Phrases that indicate Defender itself refused to scan because it is turned
# off (commonly because a third-party EDR/AV is registered as the primary AV).
_DISABLED_PHRASES = (
    "is disabled",
    "is turned off",
    "is not running",
    "service is not available",
    "deaktiviert",
    "ist deaktiviert",
    "nicht ausgeführt",
    "0x8007043c",  # ERROR_SERVICE_DISABLED
    "0x80070422",  # ERROR_SERVICE_DISABLED (alt. Code)
)


def _looks_disabled(output: str) -> bool:
    """Heuristic: did Defender report that it is disabled/unavailable?"""
    text = output.lower()
    return any(p in text for p in _DISABLED_PHRASES)


# Phrases / structured line indicating MpCmdRun bypassed the target without
# scanning it (e.g. path matches Defender's ExclusionPath or policy skip).
# _has_raw_skipped_line runs in strict O(N) without regex backtracking and
# requires MpCmdRun's trailing period ("skipped.") so a multiline echo of a
# clean extensionless file ("Scanning C:\Dir\backup was skipped\nKeine ...")
# cannot false-trigger AV_SKIPPED (Win32/NTFS strips trailing dots on files).
_SKIPPED_PHRASES = (
    "was skipped",
    "were skipped",
    "wurde übersprungen",
    "wurden übersprungen",
    "wurde uebersprungen",
    "wurden uebersprungen",
)
_SKIPPED_DE_OEM_RE = re.compile(r"(?i)\bwurden?[ \t]+\S{0,2}bersprungen\b")


def _has_raw_skipped_line(output: str) -> bool:
    """Linear-time structured check for ``Scanning <path> was|were skipped.``."""
    for line in output.splitlines():
        tokens = line.strip().lower().split()
        if (
            len(tokens) >= 4
            and tokens[0] == "scanning"
            and tokens[-2] in ("was", "were")
            and tokens[-1] == "skipped."
        ):
            return True
    return False


def _looks_skipped(output: str) -> bool:
    """Heuristic: did Defender report that scanning the target was skipped?"""
    text = output.lower()
    return any(p in text for p in _SKIPPED_PHRASES) or bool(
        _SKIPPED_DE_OEM_RE.search(text)
    )


# Phrases that indicate MpCmdRun could not actually run the scan (engine error /
# scan aborted), as opposed to a detection. In these cases MpCmdRun may still
# exit with code 2, which must NOT be read as "threat found" — otherwise every
# file becomes a false-positive critical threat. A genuine detection still names
# a threat in the output (caught via _THREAT_PHRASES) and is unaffected.
_SCAN_FAILURE_PHRASES = (
    "failed with hr",  # "CmdTool: Failed with hr = 0x80508023"
    "cmdtool: failed",
    "scan aborted",
    "0x80508023",  # scan could not be completed / aborted
)


def _looks_like_scan_failure(output: str) -> bool:
    """Heuristic: did MpCmdRun report that the scan itself failed/aborted?"""
    text = output.lower()
    return any(p in text for p in _SCAN_FAILURE_PHRASES)


# Phrases that indicate Defender took a remediation action on a detected threat
# (quarantine / removal / cleaning). Used to report *what happened* to the file.
_REMEDIATION_PHRASES = (
    "quarantined",
    "quarantine",
    "removed",
    "cleaned",
    "deleted",
    "remediated",
    "action taken",
    "successfully removed",
    "unter quarantäne",
    "in quarantäne",
    "entfernt",
    "bereinigt",
    "gelöscht",
    "maßnahme durchgeführt",
    "cleaning started",
    "cleaning finished",
)


def _remediation_detected(output: str) -> bool:
    """Heuristic: did Defender report that it remediated (acted on) a threat?"""
    text = output.lower()
    return any(p in text for p in _REMEDIATION_PHRASES)




def _platform_version_key(path: Path) -> tuple:
    """Sort key preferring the newest ``Platform\\<version>`` directory.

    Parses the numeric components of the version directory (the parent of
    ``MpCmdRun.exe``); paths without numbers sort lowest.
    """
    try:
        version_dir = path.parent.name
    except Exception:
        version_dir = ""
    nums = re.findall(r"\d+", version_dir) or re.findall(r"\d+", str(path))
    return tuple(int(x) for x in nums) if nums else (0,)


@dataclass
class AVResult:
    """Outcome of a Defender scan."""

    scanned: bool = False           # True if MpCmdRun actually ran to completion
    threat_found: bool = False      # True if a threat was detected (rc == 2)
    remediated: bool = False        # True if Defender acted on the threat
    returncode: int | None = None   # raw process return code
    detail: str = ""                # human-readable summary / captured output
    skipped_reason: str | None = None  # set when the scan could not run

    @property
    def clean(self) -> bool:
        return self.scanned and not self.threat_found


class WindowsDefenderScanner:
    """Thin, defensive wrapper around ``MpCmdRun.exe``."""

    def __init__(
        self,
        enabled: bool | None = None,
        timeout: int | None = None,
        disable_remediation: bool | None = None,
    ):
        self.enabled = config.AV_ENABLED if enabled is None else enabled
        self.timeout = config.AV_TIMEOUT_SECONDS if timeout is None else timeout
        self.disable_remediation = (
            config.AV_DISABLE_REMEDIATION if disable_remediation is None else disable_remediation
        )
        self.mpcmdrun: Path | None = self._locate() if self.enabled else None
        if self.enabled and self.mpcmdrun is None:
            # "Warum geht Defender nicht?" muss aus malaz.log beantwortbar
            # sein, ohne den Scan erneut starten zu müssen.
            log.warning(
                "MpCmdRun nicht gefunden (Kandidaten: %s) — die Defender-Stufe "
                "wird für jeden Scan übersprungen",
                list(config.AV_MPCMDRUN_CANDIDATES),
            )
        elif self.mpcmdrun is not None:
            log.info("MpCmdRun gefunden: %s", self.mpcmdrun)

    # -- discovery --------------------------------------------------------- #

    @property
    def available(self) -> bool:
        return self.enabled and self.mpcmdrun is not None

    def _locate(self) -> Path | None:
        """Find ``MpCmdRun.exe`` in known install locations.

        The ProgramData platform path carries a version wildcard and can match
        several versions side by side after updates; ``glob`` order is not
        meaningful, so the newest version is chosen deterministically. A stale
        ``MpCmdRun.exe`` would otherwise produce engine errors and silently
        disable the AV stage.
        """
        for candidate in config.AV_MPCMDRUN_CANDIDATES:
            expanded = os.path.expandvars(candidate)
            matches = [Path(m) for m in glob.glob(expanded) if Path(m).is_file()]
            if not matches:
                continue
            if len(matches) == 1:
                return matches[0]
            return max(matches, key=_platform_version_key)
        return None

    # -- scanning ---------------------------------------------------------- #

    def scan_path(self, path: Path | str) -> AVResult:
        """Scan an existing file on disk."""
        if not self.available:
            return AVResult(
                skipped_reason="Windows Defender nicht verfügbar oder deaktiviert"
            )

        # MpCmdRun aborts with an engine error (hr = 0x80508023) when handed a
        # relative path, so always pass an absolute one; resolution also keeps
        # the is_file() check and the subprocess on the same canonical target.
        target = Path(path).resolve()
        if not target.is_file():
            return AVResult(skipped_reason="Datei existiert nicht auf dem Datenträger")

        return self._run(str(target))

    def scan_bytes(self, data: bytes, suffix: str = ".bin") -> AVResult:
        """Scan in-memory bytes by staging them to a secure temp file."""
        if not self.available:
            return AVResult(
                skipped_reason="Windows Defender nicht verfügbar oder deaktiviert"
            )

        # The suffix can originate from an archive member name; sanitize it
        # centrally (ASCII-only, separators stripped, length capped).
        fd, tmp_path = tempfile.mkstemp(
            suffix=safe_temp_suffix(suffix), prefix="malaz_av_"
        )
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            return self._run(tmp_path)
        finally:
            with suppress(OSError):
                os.unlink(tmp_path)

    # -- internals --------------------------------------------------------- #

    def _run(self, target: str) -> AVResult:
        """Invoke MpCmdRun with a fixed argument list (no shell)."""
        if self.mpcmdrun is None:  # callers check .available; stay defensive
            return AVResult(skipped_reason="MpCmdRun.exe nicht gefunden")
        args = [
            str(self.mpcmdrun),
            "-Scan",
            "-ScanType",
            str(config.AV_SCAN_TYPE),
            "-File",
            target,  # single literal argv element -> no injection possible
        ]
        if self.disable_remediation:
            # Pure analysis: keep the sample on disk, do not clean/quarantine.
            args.append("-DisableRemediation")
        # A fixed 90 s timeout is wrong for a 2 GB file: it kills a scan that
        # is still making progress and turns it into AV_SKIPPED. Scale the
        # budget with the size (bounded); a timeout is still reported as
        # "not checked", never as clean.
        timeout = self.timeout
        with suppress(OSError):
            timeout = max(
                timeout, config.av_timeout_for_size(Path(target).stat().st_size)
            )
        try:
            # run_tool: no console window, hard kill on app shutdown.
            proc = run_tool(args, timeout=timeout)
        except subprocess.TimeoutExpired:
            return AVResult(
                skipped_reason=f"AV-Scan abgebrochen (Timeout > {timeout}s)"
            )
        except FileNotFoundError:
            return AVResult(skipped_reason="MpCmdRun.exe nicht gefunden")
        except Exception as exc:  # defensive: never crash the worker
            return AVResult(skipped_reason=f"AV-Scan fehlgeschlagen: {type(exc).__name__}: {exc}")

        rc, raw_out, raw_err = proc
        output = self._decode(raw_out) + self._decode(raw_err)
        output_excerpt = output.strip()[: config.MAX_STRING_CAPTURE]
        # SEC-023: the kept bytes are a prefix when the cap was hit. A threat
        # phrase or the "remediated" note can sit beyond it while the visible
        # part looks clean — so NOTHING is derived here. The scan counts as
        # not checked (AV_SKIPPED), never as clean.
        if tool_output_truncated(proc):
            log.warning(
                "MpCmdRun-Ausgabe an der Obergrenze abgeschnitten (rc=%s) — "
                "AV-Scan nicht ausgewertet, output=%r",
                rc,
                output_excerpt,
            )
            return AVResult(
                scanned=False,
                returncode=rc,
                skipped_reason=(
                    "MpCmdRun-Ausgabe wurde an der Ausgabe-Obergrenze "
                    "abgeschnitten — der AV-Scan ist NICHT ausgewertet und "
                    "nicht als 'sauber' zu werten"
                ),
                detail=output_excerpt,
            )
        # Phrase analysis runs on the output with the scanned path removed:
        # MpCmdRun echoes the path, and the path is user/attacker controlled
        # (a folder named "quarantine" or a file called "threat detected.pdf"
        # would otherwise inject verdict phrases straight from the file name).
        # strip_scan_target entfernt den Namen seit dem 22.09.2026 auch in der
        # verstuemmelten Form (Nicht-ASCII -> "?"); der frueher hier
        # beschriebene Fehlschlag bei OEM-Neukodierung ist damit behoben. Die
        # Echo-Entfernung auf Struktur bleibt als zweite Linie — sie deckt die
        # Faelle, die ueber den Namen allein nicht zu fassen sind:
        # 8.3-Kurznamen und ein Echo ohne den uebergebenen Pfad.
        #
        # SEC-018: Der strukturierte Ergebnistoken wird ZUSAETZLICH aus der
        # ROHEN Ausgabe gelesen. Heisst die Datei exakt "found 1 threats",
        # entfernt strip_scan_target nur noch den Echo; die echte
        # Ergebnistoken-Zeile bleibt stehen. Ginge sie durch eine weitere
        # Echo-Entfernung verloren, belegt der Roh-Token den Treffer. Ein
        # Treffer aus einer der beiden Quellen gewinnt immer.
        raw_structured = _structured_verdict(output)
        analysis_text = _strip_result_echo(strip_scan_target(output, target))
        verdict = _merge_verdicts(raw_structured, _verdict_from_output(analysis_text))
        scan_failed = _looks_like_scan_failure(analysis_text)
        remediated = _remediation_detected(analysis_text)
        skipped = _has_raw_skipped_line(output) or _looks_skipped(analysis_text)
        # Every AV decision is logged verbatim so a wrong verdict can be
        # diagnosed from malaz.log without re-running the scan.
        log.info(
            "MpCmdRun rc=%s verdict=%s scan_failed=%s remediated=%s skipped=%s output=%r",
            rc,
            verdict,
            scan_failed,
            remediated,
            skipped,
            output_excerpt,
        )

        # 1) Threat — the output explicitly names a threat, or return code 2 from
        #    a scan that did NOT fail. (Some Defender builds return 0 even on
        #    detection and only report the threat in the output text; the output
        #    check catches those. Conversely, a failed scan can exit with code 2
        #    while the output only shows an engine error such as "CmdTool: Failed
        #    with hr = 0x80508023" — that is NOT a detection and is handled below.)
        if verdict == "threat" or (rc == config.AV_RC_THREAT and not scan_failed):
            if remediated:
                headline = (
                    "Windows Defender hat eine Bedrohung erkannt und bereinigt "
                    "(Quarantäne/entfernt). "
                )
            elif self.disable_remediation:
                headline = (
                    "Windows Defender hat eine Bedrohung erkannt (Bereinigung "
                    "deaktiviert — Datei verbleibt auf dem Datenträger). "
                )
            else:
                headline = "Windows Defender hat eine Bedrohung erkannt. "
            return AVResult(
                scanned=True,
                threat_found=True,
                remediated=remediated,
                returncode=rc,
                detail=headline + output_excerpt,
            )

        # 2) Remediation safety net: if the output reports remediation
        #    (cleaning/removal/quarantine) yet no threat phrase matched, the
        #    verdict is contradictory — a remediated file IS a detected threat
        #    and takes precedence over both skip and clean branches.
        if remediated:
            log.warning(
                "AV-Anomalie: Bereinigung gemeldet, aber kein Treffer-Pfad "
                "(rc=%s) — als Bedrohung gewertet. output=%r",
                rc,
                output_excerpt,
            )
            return AVResult(
                scanned=True,
                threat_found=True,
                remediated=True,
                returncode=rc,
                detail=(
                    "Windows Defender hat eine Bedrohung erkannt und "
                    "bereinigt (Anomalie-Erkennung: Bereinigung ohne klaren "
                    "Treffer-Returncode). " + output_excerpt
                ),
            )

        # 3) Skipped — Defender bypassed the target (e.g. path matches an active
        #    ExclusionPath rule or policy skip) and exited with rc=0 without
        #    scanning. Must never appear as clean (completeness invariant).
        if skipped:
            return AVResult(
                scanned=False,
                returncode=rc,
                skipped_reason=(
                    "Windows Defender hat den Scan dieser Datei übersprungen "
                    "(z. B. Ausschlussliste oder Richtlinie) — Datei ist NICHT "
                    "durch Defender geprüft"
                ),
                detail=output_excerpt,
            )

        # 4) Clean — return code 0, or the output states no threats were found.
        #    The output check matters in passive mode (EDR present), where the
        #    return code can differ but the verdict is still in the text.
        #    A clean phrase must NEVER override a threat return code: the phrase
        #    may be text the strip could not attribute (attacker-controlled path
        #    echo), while the code is Defender's own. Such a case stays unclear
        #    (handled as a failed scan below) instead of being reported clean.
        if (rc == config.AV_RC_CLEAN or verdict == "clean") and rc != config.AV_RC_THREAT:
            return AVResult(
                scanned=True,
                threat_found=False,
                returncode=rc,
                detail="Windows Defender: keine Bedrohung gefunden. " + output_excerpt,
            )

        # 5) No known code and no clear verdict. If Defender reported that it is
        #    disabled (typically because a third-party EDR/AV is the primary AV
        #    and Defender is NOT in passive mode), say so explicitly.
        if _looks_disabled(analysis_text):
            return AVResult(
                scanned=False,
                returncode=rc,
                skipped_reason=(
                    "Windows Defender ist deaktiviert (vermutlich durch ein EDR/"
                    "Drittanbieter-AV) und kann im aktuellen Modus nicht scannen. "
                    "Im passiven Modus (z. B. Microsoft Defender for Endpoint) wäre "
                    "ein On-Demand-Scan möglich."
                ),
                detail=output_excerpt,
            )

        # 6) The scan itself failed/aborted (e.g. "CmdTool: Failed with hr =
        #    0x80508023"), yet MpCmdRun exited with code 2. This is an engine
        #    error, not a detection — report it inconclusive so it never inflates
        #    the score to a false-positive critical threat.
        if scan_failed:
            return AVResult(
                scanned=False,
                returncode=rc,
                skipped_reason=(
                    "AV-Scan fehlgeschlagen: MpCmdRun meldet einen Engine-Fehler "
                    "(z. B. 'CmdTool: Failed with hr = …'), keine Erkennung. "
                    "Der Returncode 2 bedeutet hier 'Scan abgebrochen', nicht "
                    "'Bedrohung gefunden'."
                ),
                detail=output_excerpt,
            )

        # 7) Generic inconclusive — must not influence the score.
        return AVResult(
            scanned=False,
            returncode=rc,
            skipped_reason=f"AV-Scan nicht aussagekräftig (Returncode {rc})",
            detail=output_excerpt,
        )

    @staticmethod
    def _decode(raw: bytes | None) -> str:
        # MpCmdRun writes OEM-codepage bytes to pipes on localized Windows;
        # UTF-8-first with an OEM fallback keeps German phrases matchable.
        return decode_tool_output(raw)
