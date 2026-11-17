"""capa integration (optional external tool, Apache-2.0).

capa (Mandiant/FLARE) answers the question the static stages cannot: not "how
does this file look" but "WHAT CAN IT DO". It names capabilities in whole
sentences ("create process", "persist via Run key", "encrypt data using AES") —
the layer DIE (format/packer) and the import heuristics (API names) do not
reach. Like DIE/ClamAV/7-Zip it is an *external* program the user installs; the
binary is NOT bundled and is invoked as a process. When it is missing the stage
is skipped gracefully with a hint.

Rule set: the standalone release of capa (``capa.exe`` from the GitHub releases)
ships a ``rules\\`` folder NEXT TO the binary and uses it automatically
("embedded rules"; verified in the upstream source ``capa/main.py``, which
resolves ``get_default_root() / "rules"``). A ``pip install flare-capa`` has no
such folder: capa then aborts with return code 10 (``E_MISSING_RULES``) and the
message "provide your own rule set via the `-r` option". For that case
``config.CAPA_RULES_CANDIDATES`` names the usual places; the first directory
that actually contains rules is passed as ``-r <dir>``. Malaz downloads
NOTHING (offline by design) — the user places the rules, and the skip message
names the path.

Security notes (see docs/SECURITY_MODEL.md):
* ``subprocess`` (via :func:`malaz.procio.run_tool`) with an argument list and
  ``shell=False``; the file path is a single literal argv element (no injection).
* the binary is resolved from fixed install locations / PATH only.
* a hard timeout bounds the run.
* capa's JSON describes an ATTACKER-CONTROLLED file and is therefore not
  trustworthy itself: only the two fields actually needed are read (rule name,
  namespace), every string is capped, the rule count is capped
  (``config.CAPA_MAX_RULES``) and the raw text is not parsed above
  ``config.CAPA_MAX_OUTPUT_CHARS``. A crafted sample must not get to decide the
  application's memory or runtime.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .. import config
from ..core.toolpath import which_absolute
from ..procio import decode_tool_output, run_tool, tool_output_truncated

log = logging.getLogger(__name__)

# capa exits with this code when it cannot find a rule set (upstream constant
# ``E_MISSING_RULES``). The stderr markers cover older builds that phrase the
# same failure differently — both are plain substring checks, no regex, so
# nothing here can backtrack on attacker input.
_RC_MISSING_RULES = 10
_MISSING_RULES_MARKERS = (
    "default embedded rules not found",
    "provide your own rule set",
    # GEMESSEN mit installiertem flare-capa 9.4.0 ohne Signaturordner: capa
    # bricht dann NICHT mit Returncode 10 ab, sondern wirft eine OSError und
    # schreibt diese Zeile. Ohne den Marker bekam der Nutzer statt des
    # hilfreichen Hinweises ein "capa-Ausgabe nicht lesbar" — und der
    # wahrscheinlichste Installationsweg (pip) trifft genau das.
    "signature path, but it doesn't exist",
    "install the signatures",
)


def _capa_disabled_hint() -> str:
    """Meldung, wenn die Stufe ABSICHTLICH aus ist.

    Nicht zu verwechseln mit "capa fehlt": hier ist alles installiert, der
    Nutzer hat die Analyse nur nicht eingeschaltet. Die Meldung nennt den
    Schalter und den Grund — gemessen 23 bis ueber 600 Sekunden je Programm.
    """
    return (
        "Die Faehigkeits-Analyse ist ausgeschaltet. Sie ist langsam: gemessen "
        "23 bis ueber 600 Sekunden je Programm, weil capa disassembliert und "
        "einen Aufrufgraphen baut. Einschalten mit CAPA_ENABLED = True "
        "(config.py) — dann dauert jede .exe/.dll entsprechend laenger."
    )


def _missing_rules_hint() -> str:
    """Skip message naming where the rules are expected.

    Built at CALL time, not at import time: the message has to name the path
    the lookup actually used.
    """
    return (
        "capa kann nicht laufen: ihm fehlen die Regelbasis und/oder die "
        "Signaturen. Das Standalone-Release bringt 'rules' und 'sigs' neben "
        "der capa.exe mit; eine per pip installierte Fassung "
        "('pip install flare-capa') nicht. Beides dorthin legen, wo capa es "
        f"erwartet (Regeln z.B. nach '{config.CAPA_RULES_CANDIDATES[0]}'). "
        "Malaz laedt weder Regeln noch Signaturen herunter — das waere ein "
        "Netzpfad."
    )


@dataclass
class CapaRule:
    """One recognised capability.

    ``name``/``namespace`` are capa's own English identifiers; ``display`` is
    what the user sees — the German category from :data:`_NAMESPACE_DE` plus the
    unchanged rule name (see :func:`capa_label`).
    """

    name: str
    namespace: str = ""
    display: str = ""


@dataclass
class CapaResult:
    scanned: bool = False
    capabilities: list[CapaRule] = field(default_factory=list)
    returncode: int | None = None
    detail: str = ""
    skipped_reason: str | None = None
    #: True when capa matched more rules than ``config.CAPA_MAX_RULES``.
    truncated: bool = False
    #: True, wenn capas Ausgabe LESBAR war — auch dann, wenn keine Regel
    #: traf. Das ist das Signal, mit dem der Aufrufer "gelaufen, nichts
    #: gefunden" von "konnte nicht laufen" unterscheidet.
    #:
    #: Ohne dieses Feld reicht ``scanned`` dafuer NICHT: der Scanner setzt
    #: ``scanned=True`` nur im Zweig mit Treffern, und ein Lauf ohne Treffer
    #: landet mit ``scanned=False`` im selben Zweig wie ein Ausfall. Ein
    #: Aufrufer, der nur auf ``scanned`` sieht, meldet dann auf JEDEM
    #: gepackten PE "capa konnte nicht laufen" — eine Falschaussage ueber eine
    #: Stufe, die sehr wohl lief.
    understood: bool = False


@dataclass
class _ParsedCapa:
    """Result of reading capa's JSON — including "was it JSON at all?".

    The distinction is the whole point: an empty ``rules`` object is a valid
    statement ("this file matches no rule") while garbled text is a broken
    invocation. Both must be reported differently, and neither may raise.
    """

    rules: list[CapaRule] = field(default_factory=list)
    truncated: bool = False
    understood: bool = False


class CapaScanner:
    """Thin wrapper around ``capa -q -j``."""

    def __init__(self, enabled: bool | None = None, timeout: int | None = None):
        self.enabled = config.CAPA_ENABLED if enabled is None else enabled
        self.timeout = config.CAPA_TIMEOUT_SECONDS if timeout is None else timeout
        self.binary: Path | None = self._locate() if self.enabled else None
        self.rules_dir: Path | None = self._locate_rules() if self.binary else None

    @property
    def available(self) -> bool:
        return self.enabled and self.binary is not None

    def _locate(self) -> Path | None:
        for candidate in config.CAPA_CANDIDATES:
            path = Path(candidate)
            if path.is_file():
                return path
        for name in ("capa", "capa.exe"):
            found = which_absolute(name)
            if found:
                return Path(found)
        return None

    def _locate_rules(self) -> Path | None:
        """External rule directory, if the user keeps one (pip installs need it).

        Only a directory that really contains ``*.yml`` rules is accepted: an
        empty folder would be handed to capa as ``-r`` and turn a working
        "embedded rules" install into a failing one.
        """
        for candidate in config.CAPA_RULES_CANDIDATES:
            path = Path(candidate)
            if path.is_dir() and next(path.glob("*.yml"), None) is not None:
                return path
        return None

    def scan_path(self, path: Path | str) -> CapaResult:
        """Run capa on an existing file; returns the recognised capabilities.

        Never raises: a missing binary, a timeout, an unreadable output and a
        completely empty result all become a ``skipped_reason``. "No
        capabilities" is the NORMAL case for packed or unusual formats — capa
        reports the reason on stderr and prints nothing useful.
        """
        if not self.available:
            return CapaResult(skipped_reason="capa nicht installiert oder deaktiviert")
        # Same contract as the other external engines: always hand over an
        # absolute path so the tool never resolves relative to its own cwd.
        target = Path(path).resolve()
        if not target.is_file():
            return CapaResult(skipped_reason="Datei existiert nicht auf dem Datenträger")
        return self._run(str(target))

    def _run(self, target: str) -> CapaResult:
        if self.binary is None:  # callers check .available; stay defensive
            return CapaResult(skipped_reason="capa nicht gefunden")
        # ``-q`` keeps the progress/diagnostic chatter off stderr (errors still
        # arrive); ``-j`` is the machine-readable output Malaz evaluates.
        args = [str(self.binary), "-q", "-j"]
        if self.rules_dir is not None:
            args += ["-r", str(self.rules_dir)]
        args.append(target)
        try:
            proc = run_tool(args, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            log.warning("capa Timeout nach %ss (target=%s)", self.timeout, target)
            return CapaResult(
                skipped_reason=f"capa-Lauf abgebrochen (Timeout > {self.timeout}s)"
            )
        except FileNotFoundError:
            return CapaResult(skipped_reason="capa nicht gefunden")
        except Exception as exc:
            log.warning(
                "capa fehlgeschlagen: %s: %s (target=%s)", type(exc).__name__, exc, target
            )
            return CapaResult(
                skipped_reason=f"capa-Lauf fehlgeschlagen: {type(exc).__name__}: {exc}"
            )

        rc, raw_out, raw_err = proc
        out = decode_tool_output(raw_out)
        err = decode_tool_output(raw_err)
        # SEC-023: a cut-off output is a PREFIX, not a document. Neither the
        # JSON nor the rule count may be derived from it — a threat-relevant
        # rule beyond the cap would silently vanish. Reported as "not checked".
        output_cut = tool_output_truncated(proc)
        # An oversized output is not parsed at all (memory), so the parse is
        # skipped up front; the decision itself is logged below.
        oversize = len(out) > config.CAPA_MAX_OUTPUT_CHARS
        parsed = (
            _ParsedCapa()
            if oversize or output_cut
            else _parse_capa_output(out)
        )
        # Every decision is logged verbatim (mirroring clamav/windows_av): a
        # stage that stays silent in the report must still be diagnosable from
        # malaz.log without re-running the scan.
        log.info(
            "capa rc=%s binary=%s rules=%s target=%s capabilities=%d truncated=%s"
            " oversize=%s output_cut=%s stderr=%r",
            rc, self.binary.name, self.rules_dir, target,
            len(parsed.rules), parsed.truncated, oversize, output_cut, _bounded(err),
        )
        if rc == _RC_MISSING_RULES or _missing_rules(err):
            return CapaResult(
                scanned=False,
                returncode=rc,
                skipped_reason=_missing_rules_hint(),
                detail=_bounded(err or out),
            )
        if output_cut:
            return CapaResult(
                scanned=False,
                returncode=rc,
                skipped_reason=(
                    "capa-Ausgabe wurde an der Ausgabe-Obergrenze abgeschnitten "
                    "— Teilausgabe nicht ausgewertet (Fähigkeiten unbekannt, "
                    "nicht als 'keine Fähigkeiten' zu werten)"
                ),
                detail=_bounded(err),
            )
        if oversize:
            # Parseable, but not worth the second copy in memory. Say so instead
            # of claiming the JSON was broken.
            return CapaResult(
                scanned=False,
                returncode=rc,
                skipped_reason="capa-Ausgabe unplausibel gross (nicht ausgewertet)",
                detail=_bounded(err),
            )
        if parsed.rules:
            return CapaResult(
                scanned=True,
                capabilities=parsed.rules,
                returncode=rc,
                detail=" | ".join(rule.display for rule in parsed.rules),
                truncated=parsed.truncated,
            )
        # Nothing usable. The reason names the ACTUAL state (a valid document
        # that matched no rule vs. text that was not JSON at all) — the
        # difference matters when the user reads it next to a packed sample.
        if parsed.understood:
            reason = "capa ohne Ergebnis (keine Fähigkeiten erkannt)"
        else:
            reason = "capa-Ausgabe nicht lesbar (kein gültiges JSON)"
        if rc:
            reason += f" (Returncode {rc})"
        return CapaResult(
            scanned=False,
            # DAS entscheidet, ob der Aufrufer meldet oder schweigt.
            understood=parsed.understood,
            returncode=rc,
            skipped_reason=reason,
            detail=_bounded(err or out),
        )


def _bounded(text: str) -> str:
    """Cap captured tool output for logs/reports (untrusted bytes)."""
    return text.strip()[: config.MAX_STRING_CAPTURE]


def _missing_rules(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _MISSING_RULES_MARKERS)


# -- German labels --------------------------------------------------------- #

# Translation of the NAMESPACE (the category), not of the rule name. The rule
# name is a technical term from the rule set — a "Run key" stays a "Run key",
# and inventing a German phrase for "create process" would hide which capa rule
# actually fired. Leading with the German category is what makes the list
# readable for the user this report is written for:
#
#     "Einrichten einer dauerhaften Autostart-Funktion: persist via Run key"
#
# Keys are namespace paths; the lookup walks from the most specific prefix down
# (see :func:`capa_label`), so only the frequent branches need an entry. A
# namespace without an entry is shown unchanged — a rule is NEVER dropped
# because it is untranslated.
# Kurze Ueberschriften fuer die GRUPPENANSICHT (gui/capability_panel).
#
# Eigene Tabelle, nicht _NAMESPACE_DE: dort stehen Verbsaetze, weil sie den
# Namen EINES Befunds bilden ("Verstecken vor Analyse: detect debugger").
# Als Ueberschrift ueber einer Liste las sich das falsch — im Screenshot stand
# "Einrichten einer dauerhaften Autostart-Funktion (2)" ueber zwei Eintraegen.
# Zwei Register, zwei Tabellen.
_GROUP_DE = {
    "persistence": "Autostart & Persistenz",
    "communication": "Netzwerk",
    "anti-analysis": "Analyse-Abwehr",
    "host-interaction": "Systemzugriff",
    "data-manipulation": "Datenveraenderung",
    "load-code": "Codeladen",
    "runtime": "Laufzeit",
    "collection": "Datensammlung",
    "executable": "Programmstart",
    "linking": "Bibliotheken",
    "nursery": "Weitere",
}

_NAMESPACE_DE = {
    "anti-analysis": "Verstecken vor Analyse",
    "anti-analysis/anti-debugging": "Schutz vor Debuggern",
    "anti-analysis/anti-static-analysis": "Schutz vor statischer Analyse",
    "anti-analysis/anti-vm": "Erkennen von Analyse-Umgebungen",
    "anti-analysis/obfuscation": "Verschleiern des Codes",
    "anti-analysis/packing": "Verpacken des Programms",
    "collection": "Sammeln von Daten",
    "collection/credit-card": "Sammeln von Kartendaten",
    "collection/keylog": "Aufzeichnen von Tastatureingaben",
    "communication": "Kontakt zu einem Server",
    "communication/c2": "Verbindung zu einem Kommandoserver",
    "communication/dns": "Namensauflösung (DNS)",
    "communication/ftp": "Dateitransfer (FTP)",
    "communication/http": "Kommunikation über HTTP",
    "communication/smtp": "Versenden von E-Mails",
    "communication/socket": "Aufbau einer Netzwerkverbindung",
    "data-manipulation": "Verändern von Daten",
    "data-manipulation/checksum": "Berechnen einer Prüfsumme",
    "data-manipulation/compression": "Komprimieren von Daten",
    "data-manipulation/encoding": "Kodieren von Daten",
    "data-manipulation/encryption": "Verschlüsseln von Daten",
    "data-manipulation/hashing": "Berechnen eines Hashes",
    "executable": "Programmdatei",
    "host-interaction": "Zugriff auf das System",
    "host-interaction/driver": "Zugriff auf einen Treiber",
    "host-interaction/file-system": "Zugriff auf Dateien",
    "host-interaction/gui": "Zugriff auf die Oberfläche",
    "host-interaction/memory": "Zugriff auf den Arbeitsspeicher",
    "host-interaction/process": "Starten von Programmen",
    "host-interaction/registry": "Zugriff auf die Registry",
    "host-interaction/service": "Einrichten eines Dienstes",
    "host-interaction/thread": "Arbeiten mit Threads",
    "impact": "Auswirkung auf das System",
    "internal": "capa-Interna",
    "lib": "Bibliotheksfunktion",
    "linking": "Einbinden von Bibliotheken",
    "load-code": "Nachladen von Code",
    "malware-family": "Malware-Familie",
    "nursery": "Experimentelle capa-Regel",
    "persistence": "Einrichten einer dauerhaften Autostart-Funktion",
    "privilege-escalation": "Ausweiten von Rechten",
    "runtime": "Laufzeitumgebung",
    "targeting": "Auswahl des Opfers",
}


def _namespace_de(namespace: str) -> str:
    """German text for a namespace path, ``""`` when nothing matches.

    Walks the path from most to least specific ("host-interaction/process/create"
    → "host-interaction/process" → "host-interaction"), so a specific entry wins
    over the general one without listing every leaf.
    """
    parts = [part for part in namespace.split("/") if part]
    for depth in range(len(parts), 0, -1):
        hit = _NAMESPACE_DE.get("/".join(parts[:depth]))
        if hit:
            return hit
    return ""


def capa_label(name: str, namespace: str) -> str:
    """Display text: German category + unchanged rule name.

    Without a translation for the namespace the rule name is shown as capa
    reports it — never omitted, never invented.
    """
    german = _namespace_de(namespace)
    return f"{german}: {name}" if german else name


# -- output parsing -------------------------------------------------------- #


def _text(value: object) -> str:
    """Read one string out of untrusted JSON, bounded in length."""
    if not isinstance(value, str):
        return ""
    return value.strip()[: config.CAPA_MAX_STRING]


def _parse_capa_output(output: str) -> _ParsedCapa:
    """Parse ``capa -j`` into capabilities.

    Shape of the result document (capa 4 to 9)::

        {"meta": {...},
         "rules": {"<name>": {"meta": {"name": ..., "namespace": ...},
                              "matches": [...]}}}

    Only ``meta.name`` and ``meta.namespace`` are read; ``matches`` (which holds
    one entry per hit address and grows with the file) is not touched at all.
    ``understood`` says whether this was a capa document at all, so the caller
    can tell "no rule matched" from "garbled output". This function never
    raises.
    """
    text = output.strip()
    if not text:
        return _ParsedCapa()
    start = text.find("{")
    if start == -1:
        return _ParsedCapa()
    try:
        # raw_decode tolerates trailing lines after the JSON object that capa may
        # append to the combined capture.
        payload, _ = json.JSONDecoder().raw_decode(text[start:])
    except (ValueError, RecursionError):
        # ValueError covers JSONDecodeError; RecursionError covers a deeply
        # nested document, which must not take the caller down either.
        return _ParsedCapa()
    if not isinstance(payload, dict):
        return _ParsedCapa()

    rules = payload.get("rules")
    if isinstance(rules, dict):
        entries: list[tuple[object, object]] = list(rules.items())
    elif isinstance(rules, list):
        entries = [(None, entry) for entry in rules]
    else:
        return _ParsedCapa()

    result = _ParsedCapa(understood=True)
    for key, entry in entries:
        if len(result.rules) >= config.CAPA_MAX_RULES:
            result.truncated = True
            break
        if not isinstance(entry, dict):
            continue
        meta = entry.get("meta")
        if not isinstance(meta, dict):
            meta = {}
        name = _text(meta.get("name")) or _text(key)
        if not name:
            continue  # nothing usable to show — not a capability
        namespace = _text(meta.get("namespace"))
        result.rules.append(
            CapaRule(name=name, namespace=namespace, display=capa_label(name, namespace))
        )
    return result
