"""Core data models shared across all layers.

Everything that crosses a layer boundary is expressed with these dataclasses so
that pipelines, scoring, reporting and the GUI agree on a single contract.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path

from .core.filesource import FileSource


class Severity(enum.IntEnum):
    """Severity of a single indicator, ordered from harmless to critical."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def label_for(self, lang: str | None = None) -> str:
        """Localized display label for this severity level."""
        from .i18n import localized_severity_label

        return localized_severity_label(self, lang=lang)

    @property
    def label(self) -> str:
        """Localized word for display (defaults to active language; ``de`` at import)."""
        return self.label_for()


class RiskLevel(enum.IntEnum):
    """Aggregated risk level of a scanned file."""

    GREEN = 0   # 0..19
    YELLOW = 1  # 20..49
    RED = 2     # 50..100

    def label_for(self, lang: str | None = None) -> str:
        from .i18n import localized_risk_label

        return localized_risk_label(self, lang=lang)

    def short_for(self, lang: str | None = None) -> str:
        from .i18n import localized_risk_short

        return localized_risk_short(self, lang=lang)

    def advice_for(self, lang: str | None = None) -> str:
        from .i18n import localized_risk_advice

        return localized_risk_advice(self, lang=lang)

    @property
    def label(self) -> str:
        return self.label_for()

    @property
    def short(self) -> str:
        """One-word verdict for laymen (used in GUI table and report badges)."""
        return self.short_for()

    @property
    def advice(self) -> str:
        """Plain-language recommendation what the user should do."""
        return self.advice_for()

    @property
    def color(self) -> str:
        return {
            RiskLevel.GREEN: "#2e7d32",
            RiskLevel.YELLOW: "#f9a825",
            RiskLevel.RED: "#c62828",
        }[self]


# Category constants used to group indicators in the report and to apply the
# anchor rule. Free-form strings keep rules flexible.
CAT_STRUCTURE = "structure"
CAT_SCRIPT = "script"
CAT_MACRO = "macro"
CAT_STEGO = "steganography"
CAT_ARCHIVE = "archive"
CAT_ENTROPY = "entropy"
CAT_SIGNATURE = "signature"
CAT_FORMAT = "format"
CAT_METADATA = "metadata"
CAT_RESOURCE = "resource"
CAT_AV = "antivirus"
CAT_CLAMAV = "antivirus"
CAT_HASHLIST = "threatintel"
CAT_IOC = "ioc"
CAT_CONTENT = "content"
# Mail-specific findings (headers, envelopes, attachments). Without this the
# phishing checks landed under "content", which reads like file contents —
# a user scanning an .eml needs to see that the *sender* or *attachment* is
# the problem, not the bytes.
CAT_MAIL = "mail"

# Plain-language explanation of each indicator category, aimed at users without
# a security background. Shown in the GUI detail panel.
# (CAT_AV and CAT_CLAMAV share the same value, hence one entry for both.)
CATEGORY_EXPLANATIONS = {
    CAT_STRUCTURE: (
        "Der innere Aufbau der Datei weicht von dem ab, was für dieses "
        "Format üblich ist."
    ),
    CAT_SCRIPT: (
        "Die Datei enthält eingebettete Skripte – kleine Programme, die "
        "automatisch starten können."
    ),
    CAT_MACRO: (
        "Die Datei enthält Makros: Mini-Programme, die beim Öffnen des "
        "Dokuments ausgeführt werden können."
    ),
    CAT_STEGO: "Hinter dem sichtbaren Inhalt könnten zusätzliche, verborgene Daten stecken.",
    CAT_ARCHIVE: "Auffälligkeiten in den gepackten Inhalten der Datei.",
    CAT_ENTROPY: (
        "Teile der Datei sind verschlüsselt oder stark komprimiert – ihr "
        "Inhalt lässt sich nicht einsehen."
    ),
    CAT_SIGNATURE: "Treffer in einer Signatur- oder Regel-Datenbank bekannter Schadsoftware.",
    CAT_FORMAT: "Die Datei gibt ein anderes Format vor, als sie tatsächlich hat.",
    CAT_METADATA: "Auffällige Metadaten, z. B. unsichtbare Inhalte oder ungewöhnliche Angaben.",
    CAT_RESOURCE: "In die Datei sind weitere Objekte oder Programme eingebettet.",
    CAT_AV: "Urteil eines auf diesem Rechner installierten Virenscanners.",
    CAT_HASHLIST: "Die Prüfsumme der Datei steht auf der lokalen Liste bekannter Schad-Dateien.",
    CAT_IOC: "Die Datei verweist auf verdächtige Internet-Adressen oder Domains.",
    CAT_CONTENT: "Im Inhalt wurden verdächtige Befehle oder Textmuster gefunden.",
    CAT_MAIL: (
        "Auffälligkeiten in der E-Mail selbst: Absender, Kopfzeilen, Links "
        "oder Anhänge deuten auf eine Täuschung hin."
    ),
}


@dataclass
class Indicator:
    """A single security finding produced by a pipeline.

    Attributes:
        rule_id:   Stable identifier of the rule/check (e.g. ``PDF_JS``).
        title:     Short human-readable summary.
        detail:    Longer explanation; may contain extracted (untrusted) data and
                   is therefore always escaped before rendering.
        severity:  Severity class.
        category:  Grouping category (one of the ``CAT_*`` constants).
        weight:    Optional explicit score weight. When ``None`` the scoring
                   engine derives it from ``severity``.
        source:    Name of the pipeline that produced the indicator.
    """

    rule_id: str
    title: str
    detail: str = ""
    severity: Severity = Severity.INFO
    category: str = CAT_STRUCTURE
    weight: int | None = None
    source: str = ""

    def effective_weight(self, base_weights: dict[Severity, int]) -> int:
        if self.weight is not None:
            return max(0, int(self.weight))
        return base_weights.get(self.severity, 0)


# Stufen, die NICHT gelaufen sind. Sie sagen nichts ueber die Datei, aber
# alles ueber die Vollstaendigkeit des Ergebnisses. EINE Liste: die Ampel, das
# Protokoll und der Kundenbericht lesen dieselbe.
#
# NUR Regeln, deren EINZIGE Bedeutung "die Stufe lief nicht" ist. Das ist
# nicht bei jeder Warnung so — GEMESSEN an zwei Faellen:
#
# * ``OFFICE_VBA_WARN`` traegt ZWEI Bedeutungen: "Makro-Projekt erkannt, aber
#   kein Quelltext ausgelesen" (eine Aussage ueber die DATEI) und "VBA-Analyse
#   fehlerhaft — Makros NICHT ausgewertet" (die Stufe). Nach der ID allein
#   laesst sich das nicht trennen; die Regel steht deshalb NICHT hier. Sonst
#   hiesse jede Datei mit einem Makro-Projekt "unvollstaendig geprueft", und
#   der Zusatz waere nach zwei Wochen Rauschen.
# * ``PDF_PARSE_WARN`` traegt drei Titel, und ALLE drei heissen "die Stufe
#   lief nicht" (Layout-Forensik fehlerhaft / PDF nicht oeffenbar /
#   Struktur-Scan fehlerhaft). Die Regel steht hier.
#
# Wer eine ergaenzt, liest zuerst ihre Titel.
_INCOMPLETE_RULES = frozenset(
    {
        # Engine-/Analyse-Stufen
        "AV_SKIPPED",
        "AV_ERROR",
        "AV_MEMBER_ERROR",
        "CLAMAV_SKIPPED",
        "CLAMAV_ERROR",
        "CLAMAV_SIZE_LIMIT",
        "CAPA_SKIPPED",
        "CAPA_UNAVAILABLE",
        "CAPA_ERROR",
        "DIE_SKIPPED",
        "DIE_ERROR",
        "YARA_SCAN_ERROR",
        "YARA_LOAD_ERROR",
        # PDF
        "PDF_LIB_MISSING",
        "PDF_PARSE_WARN",
        "PDF_JS_PARSE_WARN",
        "PDF_LINK_CAPPED",
        # Web & OneNote (Spec 014)
        "WEB_PARSE_LIMIT",
        "ONENOTE_PARSE_ERROR",
        "ONENOTE_OBJ_ERROR",
        # QR (Spec 015)
        "QR_SCAN_INCOMPLETE",
        # Office
        "OFFICE_LIB_MISSING",
        "OFFICE_STAGE_WARN",
        "OFFICE_DDE_PARSE_WARN",
        "OFFICE_XLM_PARSE_WARN",
        "OFFICE_XLM_PRESENT",
        "OFFICE_FORMULA_PARSE_WARN",
        # Mail
        "MAIL_PARSE_WARN",
        "MAIL_PARTS_TRUNCATED",
        "MAIL_REPUTATION_WARN",
        "MAIL_AUTH_DNS_UNKNOWN",
        # Lauf selbst
        "CORE_ERROR",
        "CORE_TIME_BUDGET",
        # A file above MAX_FILE_SIZE is only stat'ed; core/unchecked.py lists
        # CORE_LIMIT as "not examined" but the completeness set did not, so the
        # CSV column said "vollständig: ja" for a file that was never opened.
        "CORE_LIMIT",
        # Same contradiction for the summary note behind an unread tail
        # ("NICHT gelesen (ungeprüft)"): weight 0, but the only thing it says
        # is that a stage did not run.
        "ARCH_NOTE_UNREAD",
        # BUG-005: a scan that only saw a prefix/revision of the file said
        # "vollständig geprüft" in log, CSV and report. These three rules are
        # exactly that statement's negation and must feed the same list.
        "CORE_READ_TRUNCATED",
        "CORE_READ_SHORT",
        "CORE_FILE_CHANGED",
        "HASH_BLOCKLIST_UNAVAILABLE",
        "DOMAIN_BLOCKLIST_UNAVAILABLE",
        "IP_BLOCKLIST_UNAVAILABLE",
        "URL_BLOCKLIST_UNAVAILABLE",
    }
)


def _is_incomplete_rule(rule_id: str) -> bool:
    """True for a rule whose ONLY meaning is "this stage did not run".

    ``_INCOMPLETE_RULES`` is a closed set, but two families are generated at
    runtime and cannot be enumerated: ``EXT_<tag>_SKIPPED`` (one per
    configured external scanner) and ``EXT_<tag>_ERROR``. Both say the engine
    did not judge the file and must make the result incomplete, exactly like
    their Defender/ClamAV siblings above.
    """
    if rule_id in _INCOMPLETE_RULES:
        return True
    if rule_id.endswith("_SKIPPED"):
        return True
    return rule_id.startswith("EXT_") and rule_id.endswith("_ERROR")


@dataclass
class StageTiming:
    """One measured analysis stage (name + wall-clock duration)."""

    name: str
    duration_ms: int


@dataclass
class EngineVerdict:
    """The user-facing verdict of one engine, independent of the score."""

    engine: str
    state: str  # threat | clean | skipped | error | off
    label: str
    detail: str = ""


@dataclass
class ScanResult:
    """Aggregated result for one scanned file."""

    path: str
    size: int = 0
    sha256: str = ""
    md5: str = ""
    detected_type: str = "unknown"
    mime_hint: str = ""
    indicators: list[Indicator] = field(default_factory=list)
    score: int = 0
    risk_level: RiskLevel = RiskLevel.GREEN
    anchored: bool = False
    # Score reduction granted by clean AV verdicts (see core.scoring) — kept
    # on the result so reports can show WHY a score is lower than its raw
    # findings suggest.
    av_discount: int = 0
    duration_ms: int = 0
    # Per-stage wall-clock times, filled by the dispatcher/pipelines. Used by
    # the benchmark script; never part of the golden snapshot (timings are
    # environment-dependent).
    stage_timings: list[StageTiming] = field(default_factory=list)
    # One structured verdict per engine (Defender, ClamAV, YARA, static,
    # optional external scanners). Filled by the dispatcher after scoring;
    # the UI/report show these next to the score without parsing indicators.
    engine_verdicts: list[EngineVerdict] = field(default_factory=list)
    error: str | None = None
    # Plain-text preview of the parsed mail (headers, decoded text body,
    # annotated links, attachment names). Rendered from MailFacts — never the
    # HTML body, which is attacker-controlled. Set by the EML pipeline for an
    # .eml and by the dispatcher for an Outlook .msg (an OLE container the MIME
    # parser never sees — see core.mail_view). Empty for everything else.
    mail_preview: str = ""
    # Structured sender-security verdict for .eml/.msg, so the LIST can show it
    # without reading the preview text: {"spf": "pass|fail|none|unknown",
    # "dkim": ..., "dmarc": ..., "sender": "ok|mismatch|unknown",
    # "has_from": "1|0"} (has_from fehlt, wenn der Parser die Mail nicht lesen
    # konnte — dann ist keine Aussage ueber den Absender moeglich). Empty for
    # everything that is not a mail. The verdicts come from the mail's own
    # Authentication-Results header and are NOT verified — see mail_view.
    mail_security: dict[str, str] = field(default_factory=dict)
    # Die Links aus dem Mailrumpf, mit ihren Merkmalen. Gebraucht fuer die
    # Einzelbewertung im E-Mail-Panel (core.mail_score): "irgendwo ist ein
    # kurzer Link" hilft dem Leser nicht, "DIESER Link fuehrt woanders hin"
    # schon. Leer bei allem, was keine Mail ist.
    #
    # Als `list` ohne Elementtyp deklariert: core.eml_analysis importiert
    # dieses Modul NICHT, und ein Import hierher schloesse den Kreis.
    mail_links: list = field(default_factory=list)
    # Die von capa erkannten Faehigkeiten als ``[{"name": ..., "namespace": ...}]``.
    # Fuer den Faehigkeiten-Reiter: "was KANN dieses Programm" ist die Frage,
    # die ein Laie stellt, und eine Semikolon-Zeile im Befundtext beantwortet
    # sie nicht lesbar. Leer, wenn capa nichts gefunden hat oder fehlt.
    capa_capabilities: list = field(default_factory=list)
    # Nested results for archive members (recursion).
    children: list[ScanResult] = field(default_factory=list)
    depth: int = 0

    @property
    def display_name(self) -> str:
        if (
            self.path.startswith("(")
            and self.path.endswith(")")
            and self.path.count("(") == 1
            and self.path.count(")") == 1
            and "\\" not in self.path
        ):
            return self.path
        try:
            return Path(self.path).name
        except Exception:
            return self.path

    def all_indicators(self) -> list[Indicator]:
        """Flatten indicators of this result and all nested children."""
        out = list(self.indicators)
        for child in self.children:
            out.extend(child.all_indicators())
        return out

    @property
    def incomplete_stages(self) -> list[Indicator]:
        """Stufen, die NICHT gelaufen sind — je Ergebnis, ohne die Kinder.

        Der Grundsatz des Auftraggebers: *was wir nicht geprüft haben, darf
        nicht wie geprüft aussehen.* Ein Grün auf einer Datei, deren
        Makro-Stufe mangels Bibliothek nie lief, ist kein Freispruch.

        Diese Befunde tragen alle Gewicht 0 (eine fehlende Bibliothek ist der
        DATEI nicht anzulasten), sind aber die einzige Spur, an der sich
        „geprüft und sauber" von „nicht geprüft" unterscheiden lässt. Die
        Ampel und der Bericht lesen sie hier ab, statt die Regelnamen an
        vier Stellen aufzuzählen.

        ``all_indicators`` taugt dafür NICHT: es zieht die Kinder mit herein,
        und ein sauberes Elternteil sähe dann wegen eines Kindes unvollständig
        aus.
        """
        return [i for i in self.indicators if _is_incomplete_rule(i.rule_id)]

    @property
    def is_incomplete(self) -> bool:
        """Ist an dieser Datei etwas NICHT geprüft worden?"""
        return bool(self.incomplete_stages)

    def incompleteness_note(self, lang: str | None = None) -> str:
        """Ein Satz für die Anzeige — oder leer, wenn alles lief."""
        stufen = self.incomplete_stages
        if not stufen:
            return ""
        from .i18n import get_language, localized_indicator_title, resolve_language, t

        eff = resolve_language(lang) if lang is not None else get_language()
        if eff in ("en", "tr"):
            names = " | ".join(
                localized_indicator_title(i, lang=eff) for i in stufen
            )
            return t(
                "report.incomplete_note",
                lang=eff,
                count=len(stufen),
                names=names,
            )
        namen = " | ".join(i.title for i in stufen)
        return t(
            "report.incomplete_note",
            lang="de",
            count=len(stufen),
            names=namen,
        )


@dataclass
class AnalysisContext:
    """Everything a pipeline needs to analyse one file.

    The raw bytes are pre-capped to ``config.MAX_READ_SIZE`` by the dispatcher;
    ``sha256`` carries the hash of the *complete* file on disk (streamed), so
    hash-based checks (blocklist) stay correct for files larger than the read
    cap. Archive members (fully in memory) pass the hash of their bytes.
    """

    path: Path
    data: bytes
    detected_type: str
    size: int
    # Path-backed source for files larger than MAX_READ_SIZE. ``data`` is then
    # a bounded prefix; streaming consumers use ``source`` instead.
    source: FileSource | None = None
    # Per-file time budget (time.monotonic) for streaming consumers; None for
    # ordinary in-memory scans.
    deadline: float | None = None
    depth: int = 0
    # Optional display path for archive members (relative inside the archive).
    display_path: str = ""
    # Full-file SHA-256 (hex); empty when computed from ``data`` is equivalent.
    sha256: str = ""
    # Output channel for the same purpose, structured: the pipeline fills it
    # with the per-mechanism verdicts and the sender comparison, the dispatcher
    # copies it onto the result.
    mail_security: dict[str, str] = field(default_factory=dict)
    # Derselbe Kanal fuer die Linkliste des Rumpfs (siehe ScanResult.mail_links).
    mail_links: list = field(default_factory=list)
    # Derselbe Kanal fuer die capa-Faehigkeiten.
    capa_capabilities: list = field(default_factory=list)
    # Output channel for a pipeline that extracts a *preview* worth showing:
    # currently the plain-text mail view (from the EML pipeline for an .eml, set
    # directly by the dispatcher for an Outlook .msg). The dispatcher copies it
    # onto the result after the pipelines ran, so the GUI/report get it without
    # a second parse. Pipelines otherwise only return indicators; this is
    # deliberately a single, narrow field rather than a general bus.
    preview: str = ""

    def __post_init__(self) -> None:
        if not self.display_path:
            try:
                self.display_path = self.path.name
            except Exception:
                self.display_path = str(self.path)


# -- human-readable file types -------------------------------------------------- #
#
# The raw ``detected_type`` values are internal identifiers ("eml", "pe",
# "ps1"). Showing them verbatim in the GUI and both reports made the tool read
# like a debug console — a user who just received a phishing mail needs to see
# "E-Mail-Nachricht", and one who scanned a download needs "Programm (EXE)"
# rather than "pe". The mapping lives here so all three surfaces agree.
#
# ``mail_kind`` is separate: an .eml and a .msg are both "E-Mail", but only the
# one carrying the full header set is reported as a message file.
TYPE_LABELS: dict[str, str] = {
    # documents
    "pdf": "PDF-Dokument",
    "ole": "Office-Dokument (alt)",
    "zip": "ZIP-Archiv",
    "eml": "E-Mail-Nachricht",
    "rtf": "RTF-Dokument",
    # images
    "png": "PNG-Bild",
    "jpeg": "JPEG-Bild",
    # HEIC/HEIF und AVIF: ISO-BMFF-Fotos (iPhone, Kameras). Ohne Label zeigt
    # die GUI-Spalte "Typ" und der Kunden-PDF den rohen Token.
    "heic": "HEIC-Foto",
    "avif": "AVIF-Bild",
    "gif": "GIF-Bild",
    "bmp": "BMP-Bild",
    "tiff": "TIFF-Bild",
    "webp": "WebP-Bild",
    "ico": "Windows-Symbol (.ico)",
    "mp3": "MP3-Audiodatei",
    "mp4": "Video (MP4/QuickTime)",
    # executables
    "pe": "Programm (EXE/DLL)",
    "elf": "Programm (Linux)",
    "macho": "Programm (macOS)",
    "class": "Java-Klasse",
    # archives
    "rar": "RAR-Archiv",
    "7z": "7-Zip-Archiv",
    "gzip": "GZip-Archiv",
    "bzip2": "BZip2-Archiv",
    "xz": "XZ-Archiv",
    "tar": "TAR-Archiv",
    "cab": "CAB-Archiv",
    "iso": "ISO-Abbild",
    "chm": "Windows-Hilfedatei (.chm)",
    "vhdx": "Virtuelles Laufwerk (.vhdx)",
    "ntfs": "NTFS-Dateisystemabbild",
    "fat": "FAT/exFAT-Dateisystemabbild",
    "onenote": "OneNote-Dokument (.one)",
    "deb": "Debian-Paket",
    "rpm": "RPM-Paket",
    # text and scripts
    "text": "Textdatei",
    "html": "HTML-Seite",
    "xml": "XML-Datei",
    "json": "JSON-Datei",
    "batch": "Windows-Stapeldatei (.bat)",
    "ps1": "PowerShell-Skript",
    "vbs": "VBScript-Datei",
    "js": "JavaScript-Datei",
    "swf": "Flash-Datei (SWF)",
    "lnk": "Windows-Verknüpfung (.lnk)",
    "url": "Internet-Verknüpfung (.url)",
    # fallbacks
    "empty": "Leere Datei",
    "unknown": "Unbekannter Typ",
}


def type_label(detected_type: str, *, lang: str | None = None) -> str:
    """Human-readable name for a detected type (falls back to the raw value).

    Unknown values are passed through unchanged rather than hidden: a new
    format must stay visible instead of silently reading "Unbekannt".
    """
    from .i18n import get_language, localized_type_label, resolve_language

    eff = resolve_language(lang) if lang is not None else get_language()
    if eff in ("en", "tr"):
        return localized_type_label(detected_type, lang=eff)
    return TYPE_LABELS.get((detected_type or "").lower(), detected_type or "—")


def type_description(
    detected_type: str, mime_hint: str = "", *, lang: str | None = None
) -> str:
    """``Label (mime)`` for detail views; the MIME part is optional."""
    label = type_label(detected_type, lang=lang)
    return f"{label} ({mime_hint})" if mime_hint else label


def category_explanation(category: str, *, lang: str | None = None) -> str:
    """Localized plain-language explanation for an indicator category."""
    from .i18n import localized_category_explanation

    return localized_category_explanation(category, CATEGORY_EXPLANATIONS, lang=lang)
