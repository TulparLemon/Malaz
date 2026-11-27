"""Generic pipeline: runs for every file.

Stages (all cheap and static):

1. Shannon entropy (vectorized NumPy) — packed/encrypted/hidden payloads.
2. YARA signature scan.
3. Format consistency (extension vs. header bytes).
4. SHA-256 blocklist (offline threat intelligence) — CRITICAL anchor on hit.
5. Content heuristics on text-like / LNK files: suspicious command strings,
   extracted IOCs (URLs, IPv4, domains) and parsed LNK target/arguments.
6. Address extraction from the RAW BYTES of everything that is not decoded as
   text (PE/ELF/Mach-O, PDF, OLE, images, archives) — see core/binary_iocs.
"""

from __future__ import annotations

import ipaddress
import os
import re
import struct
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlsplit

from .. import config
from ..core.binary_iocs import (
    BINARY_IOC_BLOCKED_TITLE,
    BLOCKLIST_UNAVAILABLE_TITLE,
    IOC_DOMAIN,
    IOC_IPV4,
    IOC_IPV6,
    IOC_URL,
    TLD_ALTERNATION,
    capped_ioc_kinds,
    extract_binary_iocs,
    extract_binary_iocs_stream,
    split_blocked_iocs,
)
from ..core.eml_parser import classify_url
from ..core.entropy import (
    entropy_indicator_weight,
    shannon_entropy,
    shannon_entropy_chunks,
)
from ..core.filename_iocs import match_filename_iocs
from ..core.hashlist import is_listed_with_status, matched_source
from ..core.js_deobf import deobfuscate_js_detailed
from ..core.lnk import parse_lnk
from ..core.magic import expected_type_for_extension
from ..core.script_deobf import (
    REASON_INPUT_LIMIT,
    DeobfBudget,
    ScriptDeobfResult,
    decode_powershell_encoded,
    deobfuscate_batch,
    deobfuscate_powershell,
    extract_vba_strings,
)
from ..core.suspicious_tokens import SUSPICIOUS_COMMAND_TOKENS as _SUSPICIOUS_TOKENS
from ..core.url_view import defang_url
from ..core.yara_engine import YaraEngine
from ..models import (
    CAT_CONTENT,
    CAT_ENTROPY,
    CAT_FORMAT,
    CAT_HASHLIST,
    CAT_IOC,
    CAT_METADATA,
    CAT_SCRIPT,
    CAT_SIGNATURE,
    AnalysisContext,
    Indicator,
    Severity,
)
from .base import Pipeline

# PowerShell download-cradle: a download primitive combined with an execution
# primitive describes the classic "fetch & run" chain (both groups must match).
_PS_CRADLE_DOWNLOAD = (
    "downloadstring",
    "downloadfile",
    "downloaddata",
    "net.webclient",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "urlcache",
)
_PS_CRADLE_EXEC = (
    "invoke-expression",
    "iex(",
    "iex ",
    "iex$",
    ".invoke(",
    "start-process",
)

# LOLBin abuse: binary name + a characteristic abuse argument (both required),
# which is far more specific than the bare binary name in _SUSPICIOUS_TOKENS.
_LOLBIN_ABUSE = (
    ("certutil", ("-urlcache", "-verifyctl", "urlcache")),
    ("regsvr32", ("/i:http", "/i:ftp", "scrobj.dll")),
    ("mshta", ("vbscript:", "javascript:", ".hta")),
    ("rundll32", ("javascript:", "vbscript:", "shellexecrunhtml.dll")),
    ("wmic", ("process call create", "/format:", "os get")),
    ("bitsadmin", ("/transfer", "/addfile")),
    ("installutil", ("/logfile=", "/u ")),
    ("odbcconf", ("/a ", "regsvr")),
)

_URL_RE = re.compile(rb"https?://[^\s\"'<>)]{6,256}", re.IGNORECASE)
_IPV4_RE = re.compile(
    rb"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)"
)
# A rough domain heuristic: label.label.tld with a known-ish TLD set, excluding
# common benign hosts to cut noise. The TLD set itself lives in
# core/binary_iocs.py: the raw-byte path (PE/PDF/OLE/images/archives) asks the
# same question and must not answer it differently — two copies would drift.
_DOMAIN_RE = re.compile(
    rb"(?<![.\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    + TLD_ALTERNATION
    + rb"(?![.\w])",
    re.IGNORECASE,
)
_BENIGN_HOSTS = (
    "microsoft.com",
    "windows.com",
    "mozilla.org",
    "w3.org",
    "schemas.openxmlformats.org",
    "purl.org",
    "example.com",
    "localhost",
)

# Types whose content is decoded as text and run through the text heuristics
# (suspicious strings, PowerShell, GEN_IOC). Everything NOT in here has no
# address check at all unless the raw-byte stage below covers it.
#
# Script dialects refine "text" (magic.refine_text_type) — they MUST stay in
# this set: excluding them would silently drop the suspicious-string/PowerShell
# checks from the very files they were built for.
_TEXT_CONTENT_TYPES = frozenset(
    {
        "text", "html", "xml", "eml", "json", "unknown",
        # swf: after decompression the payload is readable — ActionScript
        # strings and URLs are exactly what the SWF stage is for.
        "swf",
        "batch", "ps1", "vbs", "js",
    }
)

# Addresses found in raw bytes: severity/weight and title per rule, kept in
# tables so a new rule cannot silently fall back to a default (the same trap
# the mail pipeline guards with a test). A blocklist hit is a finding; an
# unknown address is information only — it must be visible without driving the
# score.
_BINARY_IOC_LEVELS = {
    "BINARY_IOC_BLOCKED": (Severity.HIGH, 30),
    "BINARY_IOC": (Severity.INFO, 0),
    "BINARY_IOC_CAPPED": (Severity.INFO, 0),
}
_BINARY_IOC_TITLES = {
    "BINARY_IOC_BLOCKED": BINARY_IOC_BLOCKED_TITLE,
    "BINARY_IOC": "Adressen im Binärinhalt",
    "BINARY_IOC_CAPPED": "Adressprüfung durch Trefferdeckel begrenzt",
}
# Display order/labels for the finding text, one per IOC_* kind.
_BINARY_IOC_LABELS = (
    (IOC_URL, "URLs"),
    (IOC_IPV4, "IPv4"),
    (IOC_IPV6, "IPv6"),
    (IOC_DOMAIN, "Domains"),
)


def _complete_file(ctx: AnalysisContext) -> Path | None:
    """Die analysierte Datei auf der Platte, wenn ``ctx`` für das *ganze* File steht.

    Archiv-Mitglieder werden aus dem Speicher analysiert (ihr ``path`` ist der
    Name im Archiv, keine Datei), und eine Stufe, die dort rät, würde am Ende
    die falsche Datei beurteilen. Deshalb nur auf oberster Ebene (``depth`` 0)
    und nur, wenn die Größe zur Angabe des Aufrufers passt.
    """
    if ctx.depth:
        return None
    try:
        path = Path(ctx.path)
        if path.is_file() and path.stat().st_size == ctx.size:
            return path
    except OSError:
        return None
    return None


def _pdf_compression_explained(ctx: AnalysisContext) -> bool:
    """True when the PDF's object graph really declares compression/encryption.

    The declaration has to live IN the document, not merely in its bytes. The
    previous marker probe accepted the ASCII bytes ``/FlateDecode`` anywhere —
    measured: 12 inserted characters lowered a PDF with 32 KB of random payload
    from GELB 30 to GRÜN 5, and the same trick works inside a comment or a dead
    object. Parsing decides by structure instead: an encrypted document, or a
    stream that actually carries a filter.

    Parsed is the *complete* file when the analysed path is the whole file —
    ``ctx.data`` is capped at ``config.READ_CHUNK_SIZE`` (1 MiB), and a large
    scanned document truncated there keeps its page tree but loses the stream
    dictionary; it would then be read as "packed".
    """
    import io

    try:
        import pikepdf
    except Exception:
        # Ohne Parser gibt es keine belegte Erklärung — dann bleibt es strikt.
        return False
    source = _complete_file(ctx)
    try:
        with pikepdf.open(source if source is not None else io.BytesIO(ctx.data)) as pdf:
            if getattr(pdf, "is_encrypted", False):
                return True
            return any(
                isinstance(obj, pikepdf.Stream)
                and obj.get(pikepdf.Name.Filter) is not None
                for obj in pdf.objects
            )
    except pikepdf.PasswordError:
        # Der Parser braucht das Passwort: damit ist die Verschlüsselung
        # nachgewiesen, und genau sie soll die Entropie erklären.
        return True
    except Exception:
        return False


# Whole-file entropy is judged against the format's expected baseline (the
# way established triage tools do it — e.g. Sandfly's entropyscan whitelists
# compressed formats by signature): a format whose SPEC includes compression
# sits at ~7.5-8 bit/byte anyway, so high entropy there is noise, not a
# finding. Three tiers, one per kind of baseline:
#
# 1. Archives/containers (below): entropy of the CONTAINER is meaningless
#    because Malaz recurses into the members (7-Zip) — the member pipelines
#    apply all rules, including entropy, where they are actually valid.
# 2. Atomic, spec-compressed formats: visible LOW note with capped weight
#    (transparency — there is no deeper recursion that could show it).
# 3. Everything else (PE/ELF/Mach-O/OLE/RTF/Java-class/BMP/unknown):
#    strict — those formats have a plaintext or uncompressed baseline, so
#    high entropy really does mean packed/embedded/hidden content.
_ENTROPY_ARCHIVE_TYPES = frozenset({
    "zip", "rar", "7z", "tar", "deb", "rpm",
    # Cabinet/ISO were missing from the original skip list — latent false
    # positives exactly like the .deb/.rpm field report.
    "cab", "iso",
    # Spec 014: CHM (LZX), VHDX/NTFS/FAT disk images and OneNote containers
    # (which routinely embed compressed PNG/JPEG screenshots) are judged via
    # their unpacked children rather than raw container entropy.
    "chm", "vhdx", "ntfs", "fat", "onenote",
})

# Atomic formats that are compressed by specification. SWF is deliberately
# absent: only the CWS (zlib) and ZWS (LZMA) variants are compressed — an
# FWS (uncompressed) SWF with ~8 bit/byte is genuinely anomalous.
_ENTROPY_SPEC_COMPRESSED = frozenset({
    "jpeg", "png", "gif",          # DCT / zlib-IDAT / LZW
    # HEIC/HEIF und AVIF sind HEVC- bzw. AV1-komprimiert — ein normales Foto
    # hat dort IMMER nahe 8 bit/Byte. GEMESSEN: ein HEIC ergab Score 30/GELB,
    # weil der Typ als "unknown" gelesen wurde und die Erklaerung nicht griff.
    "heic", "avif",
    # WebP/MP3/MP4 sind ebenfalls spezifikationskomprimiert (VP8/VP8L,
    # MPEG-Audio, H.264/HEVC/AV1 im Container). Ein normales Medium liegt
    # dort bei 7.5-8 bit/Byte; die Entropie ist Formatrauschen, kein Packer.
    # TIFF und ICO stehen hier BEWUSST NICHT: beide koennen unkomprimierte
    # Rohdaten tragen, dort bleibt hohe Entropie ein echter Hinweis.
    "webp", "mp3", "mp4",
    "gzip", "bzip2", "xz",         # compressed single-file streams
})


def _compression_explanation(ctx: AnalysisContext) -> str | None:
    """Why high entropy is normal for this file, or ``None`` if it is not."""
    ftype = ctx.detected_type
    data = ctx.data
    if ftype == "pdf" and _pdf_compression_explained(ctx):
        return "die im PDF deklarierten Kompressions-/Verschlüsselungs-Streams"
    if ftype in _ENTROPY_SPEC_COMPRESSED:
        return f"das {ftype.upper()}-Format selbst (spezifikationsgemäß komprimiert)"
    if ftype == "swf" and data[:3] in (b"CWS", b"ZWS"):
        return "die komprimierte SWF-Variante (CWS/ZWS-Header)"
    if ftype == "pe":
        # Die Verifikation nur für ein PE mit hoher Entropie anfordern — sonst
        # würde jede Datei eine PowerShell-Runde kosten.
        from .pe_pipeline import authenticode_explains_entropy, authenticode_status

        # A verified Authenticode signature explains high entropy: installers
        # and self-extracting packages (PyInstaller, Inno Setup, …) carry a
        # compressed payload (measured: "Uninstall ZCode.exe" reached RED on
        # entropy + overlay alone). "Signed" is the verifier's answer, never
        # the sample's claim; the control lives in pe_pipeline so the overlay
        # classification and this explanation cannot drift apart.
        if authenticode_explains_entropy(data, authenticode_status(ctx)):
            return "ein digital signiertes, selbstentpackendes Paket (Signatur verifiziert)"
    return None


class GenericPipeline(Pipeline):
    name = "generic"

    def __init__(self, yara: YaraEngine | None = None):
        self.yara = yara

    def analyze(self, ctx: AnalysisContext) -> list[Indicator]:
        indicators: list[Indicator] = []
        indicators.extend(self._entropy(ctx))
        indicators.extend(self._yara(ctx))
        indicators.extend(self._format_consistency(ctx))
        indicators.extend(self._bidi_filename(ctx))
        indicators.extend(self._hash_blocklist(ctx))
        if config.GENERIC_CONTENT_CHECKS:
            indicators.extend(self._content_checks(ctx))
        indicators.extend(self._filename_ioc(ctx))
        indicators.extend(self._motw(ctx))
        indicators.extend(self._script_note(ctx))
        if config.EMBEDDED_SIGNATURE_SCAN:
            indicators.extend(self._embedded_signatures(ctx))
        return indicators

    # -- script framing ---------------------------------------------------- #

    # Content heuristics (suspicious tokens, encoded PowerShell, download
    # cradles, LOLBins) already live in _content_checks and run for every
    # decodable file. What was missing is the TYPE framing: a .bat shown as
    # "Text" hides that opening it executes code.
    _SCRIPT_LABELS: ClassVar[dict[str, str]] = {
        "batch": "Batch-Skript (.bat/.cmd)",
        "ps1": "PowerShell-Skript (.ps1)",
        "vbs": "VBScript (.vbs)",
        "js": "JavaScript (.js)",
    }

    def _script_note(self, ctx: AnalysisContext) -> list[Indicator]:
        label = self._SCRIPT_LABELS.get(ctx.detected_type)
        if label is None:
            return []
        return [
            self._indicator(
                "SCRIPT_EXECUTABLE",
                f"{label}: ausführbarer Inhalt",
                detail=(
                    "Diese Datei ist ein Skript — Öffnen/Ausführen führt Code "
                    "auf dem Rechner aus. Malaz bewertet den Inhalt rein statisch "
                    "(Befehle, Obfuskierung, Download-Muster); das ersetzt keine "
                    "Verhaltensanalyse in einer isolierten Umgebung."
                ),
                severity=Severity.INFO,
                category=CAT_SCRIPT,
                weight=0,
            )
        ]

    # -- entropy ----------------------------------------------------------- #

    def _entropy(self, ctx: AnalysisContext) -> list[Indicator]:
        if not ctx.data:
            return []
        if ctx.detected_type in _ENTROPY_ARCHIVE_TYPES:
            # Container entropy is meaningless — members are analysed
            # recursively and judged there, where the rules are valid.
            return []
        source = getattr(ctx, "source", None)
        if source is not None and source.size > len(ctx.data):
            entropy = shannon_entropy_chunks(
                source.iter_chunks(deadline=getattr(ctx, "deadline", None))
            )
        else:
            entropy = shannon_entropy(ctx.data)
        weight = entropy_indicator_weight(entropy)
        if weight <= 0:
            return []
        # Severity threshold mirrors the weight threshold (config-driven, so
        # the level can never drift from the score).
        severity = Severity.HIGH if entropy >= config.ENTROPY_VERY_HIGH else Severity.MEDIUM
        detail = (
            "Ein sehr hoher Informationsgehalt deutet auf verschlüsselte, "
            "gepackte oder versteckte Nutzdaten hin."
        )
        # High entropy that the format spec explains is a note, not a
        # finding: Malaz's own PDF report scored 27/GELB and a field-report
        # JPEG 26/GELB on this signal alone. Keep it visible as LOW with a
        # capped weight; everything without an explanation stays strict.
        explanation = _compression_explanation(ctx)
        if explanation:
            weight = min(weight, config.ENTROPY_EXPLAINED_CAP)
            severity = Severity.LOW
            detail = (
                f"Hohe Entropie ist hier durch {explanation} erklärbar "
                "(Normalfall bei diesem Format); sie allein ist kein Hinweis "
                "auf Schadcode."
            )
        return [
            self._indicator(
                "GEN_ENTROPY",
                f"Hohe Shannon-Entropie ({entropy:.2f} bit/Byte)",
                detail=detail,
                severity=severity,
                category=CAT_ENTROPY,
                weight=weight,
            )
        ]

    # -- yara -------------------------------------------------------------- #

    def _yara(self, ctx: AnalysisContext) -> list[Indicator]:
        if self.yara is None or not ctx.data:
            return []
        source = getattr(ctx, "source", None)
        if source is not None and source.size > len(ctx.data):
            outcome = self.yara.scan_file_with_status(source.path)
        else:
            outcome = self.yara.scan_with_status(ctx.data)
        out: list[Indicator] = []
        if outcome.load_error:
            out.append(
                self._indicator(
                    "YARA_LOAD_ERROR",
                    "YARA-Regeln konnten nicht vollständig geladen werden",
                    detail=(
                        f"{outcome.load_error} — mindestens ein Regelsatz wurde "
                        "nicht ausgewertet; ein Treffer darin wäre unentdeckt "
                        "geblieben."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_SCRIPT,
                    weight=25,
                )
            )
        if outcome.scan_error:
            out.append(
                self._indicator(
                    "YARA_SCAN_ERROR",
                    "YARA-Stufe nicht vollständig gelaufen",
                    detail=(
                        f"{outcome.scan_error} — dieser Teil der Regeln wurde "
                        "NICHT ausgewertet; ein Treffer darin wäre unentdeckt "
                        "geblieben."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_SCRIPT,
                    weight=25,
                )
            )
        for match in outcome.matches:
            detail = match.description
            if match.author:
                detail = f"{detail}\nAutor: {match.author}"
            if match.matched_strings:
                detail += " | Treffer: " + ", ".join(match.matched_strings[:8])
            out.append(
                self._indicator(
                    f"YARA_{match.rule}",
                    f"YARA-Treffer: {match.rule}",
                    detail=detail,
                    severity=match.severity,
                    category=CAT_SIGNATURE,
                    weight=match.weight,
                )
            )
        return out

    # -- format consistency ------------------------------------------------ #

    def _format_consistency(self, ctx: AnalysisContext) -> list[Indicator]:
        try:
            ext = "." + ctx.path.suffix.lstrip(".").lower() if ctx.path.suffix else ""
        except Exception:
            return []
        if not ext:
            return []
        expected = expected_type_for_extension(ext)
        if expected is None or expected == ctx.detected_type:
            return []
        if ctx.detected_type in ("unknown", "empty"):
            return []
        return [
            self._indicator(
                "GEN_FORMAT_MISMATCH",
                f"Format-Täuschung: Endung {ext} ≠ Inhalt ({ctx.detected_type})",
                detail=(
                    f"Die Dateiendung '{ext}' behauptet '{expected}', die Header-Bytes "
                    f"zeigen jedoch '{ctx.detected_type}'. Mögliche Verschleierung."
                ),
                severity=Severity.HIGH,
                category=CAT_FORMAT,
            )
        ]

    # -- BiDi / RLO filename spoofing -------------------------------------- #

    @staticmethod
    def _has_bidi_control(text: str) -> bool:
        return any(
            0x202A <= ord(ch) <= 0x202E or 0x2066 <= ord(ch) <= 0x2069
            for ch in text
        )

    @staticmethod
    def _display_leaf(display_path: str) -> str:
        """Extract only the final leaf filename from a container display path."""
        if not display_path:
            return ""
        # Container chains use " -> " or " :: " or path separators; inspect only the leaf
        # so a BiDi character in a parent archive name does not falsely flag a clean child.
        leaf = display_path
        for sep in (" -> ", " :: ", "/", "\\"):
            if sep in leaf:
                leaf = leaf.rsplit(sep, 1)[-1]
        return leaf.strip()

    def _bidi_filename(self, ctx: AnalysisContext) -> list[Indicator]:
        r"""Flag Unicode BiDi override/isolate controls in filenames (RLO trick).

        Characters U+202A..U+202E and U+2066..U+2069 visually reverse extensions
        (e.g. ``Rechnung\u202efdp.exe`` renders as ``Rechnungexe.pdf`` in
        Windows Explorer). Genuine RTL letters (Arabic/Hebrew) are untouched.
        """
        candidates = []
        if ctx.path:
            candidates.append(ctx.path.name)
        if ctx.display_path:
            candidates.append(self._display_leaf(ctx.display_path))
        if not any(self._has_bidi_control(name) for name in candidates if name):
            return []
        return [
            self._indicator(
                "GEN_BIDI_NAME",
                "Dateiname enthält unsichtbare Richtungssteuerung (RLO/BiDi)",
                detail=(
                    "Der Dateiname enthält Unicode-BiDi-Steuerzeichen (z. B. U+202E), "
                    "mit denen echte Dateiendungen optisch getarnt werden."
                ),
                severity=Severity.CRITICAL,
                category=CAT_FORMAT,
                weight=50,
            )
        ]

    # -- hash blocklist ---------------------------------------------------- #

    def _hash_blocklist(self, ctx: AnalysisContext) -> list[Indicator]:
        if not ctx.data:
            return []
        import hashlib

        # Prefer the full-file hash provided by the dispatcher: for files larger
        # than the read cap, ctx.data is truncated and its hash would never
        # match the blocklist.
        digest = ctx.sha256 or hashlib.sha256(ctx.data).hexdigest()
        listed, errors = is_listed_with_status(digest)
        out: list[Indicator] = []
        if listed:
            # Name the list that actually matched — a hit can come from the
            # curated file or the user's imported list, and naming a fixed path
            # would be wrong for one of them.
            source = matched_source(digest)
            detail = f"Hash {digest} steht auf der lokalen Blocklist"
            detail += f" ({source})." if source else "."
            out.append(
                self._indicator(
                    "GEN_HASH_BLOCKLIST",
                    "SHA-256 auf lokaler Blocklist (Threat-Intel)",
                    detail=detail,
                    severity=Severity.CRITICAL,
                    category=CAT_HASHLIST,
                    weight=50,
                )
            )
        if errors:
            out.append(
                self._blocklist_unavailable(
                    "HASH_BLOCKLIST_UNAVAILABLE",
                    "Die lokale SHA-256-Blockliste konnte nicht gelesen werden; "
                    "der Hash-Abgleich ist unvollständig.",
                )
            )
        return out

    def _blocklist_unavailable(self, rule_id: str, detail: str) -> Indicator:
        """Create the zero-weight, visible marker for a failed local list."""
        return self._indicator(
            rule_id,
            BLOCKLIST_UNAVAILABLE_TITLE,
            detail=detail + " Das Ergebnis ist an dieser Stelle unvollständig.",
            severity=Severity.INFO,
            category=CAT_IOC,
            weight=0,
        )

    # -- filename IOCs ------------------------------------------------------ #

    def _filename_ioc(self, ctx: AnalysisContext) -> list[Indicator]:
        """Match the file path against the local IOC rules (Loki-style)."""
        path_text = str(ctx.path) if ctx.depth == 0 else ctx.display_path or str(ctx.path)
        hits = match_filename_iocs(path_text)
        if not hits:
            return []
        out: list[Indicator] = []
        for hit in hits:
            if hit.score >= config.FILENAME_IOC_SCORE_CRITICAL:
                severity, weight = Severity.CRITICAL, 50
            elif hit.score >= config.FILENAME_IOC_SCORE_HIGH:
                severity, weight = Severity.HIGH, 30
            elif hit.score >= 15:
                severity, weight = Severity.MEDIUM, 15
            else:
                severity, weight = Severity.LOW, 5
            detail = f"Regex: {hit.pattern}"
            if hit.description:
                detail += f" — {hit.description}"
            out.append(
                self._indicator(
                    "GEN_FILENAME_IOC",
                    "Dateiname-IOC-Treffer",
                    detail=detail,
                    severity=severity,
                    category=CAT_IOC,
                    weight=weight,
                )
            )
        return out

    # -- Mark of the Web (Windows Zone.Identifier ADS) ---------------------- #

    # Only zones 3 (Internet) and 4 (Restricted) are reported; _motw returns
    # an empty list for every other zone, so no other label can be reached.
    _ZONE_NAMES: ClassVar[dict[str, str]] = {
        "3": "Internet",
        "4": "Eingeschränkt",
    }

    def _motw(self, ctx: AnalysisContext) -> list[Indicator]:
        """Flag files downloaded from the internet (NTFS Zone.Identifier)."""
        if os.name != "nt" or ctx.depth != 0:
            return []
        try:
            target = Path(ctx.path)
            if not target.is_file():
                return []
            with open(str(target) + ":Zone.Identifier", "rb") as fh:
                raw = fh.read(4096)
        except OSError:
            return []  # no ADS (FAT/exFAT/network) or not downloaded
        text = raw.decode("utf-8", errors="replace")
        zone = ""
        referrer = ""
        host = ""
        for line in text.splitlines():
            key, _, value = line.partition("=")
            key = key.strip().lower()
            value = value.strip()
            if key == "zoneid":
                zone = value
            elif key == "referrerurl":
                referrer = value
            elif key == "hosturl":
                host = value
        if zone not in ("3", "4"):
            return []
        detail = f"Zone: {self._ZONE_NAMES.get(zone, zone)}"
        if referrer:
            detail += f" | Referrer: {referrer}"
        if host:
            detail += f" | Host: {host}"
        return [
            self._indicator(
                "GEN_MOTW",
                "Datei aus dem Internet heruntergeladen",
                detail=detail,
                severity=Severity.LOW,
                category=CAT_METADATA,
                weight=5,
            )
        ]

    # -- embedded signature scan -------------------------------------------- #

    def _embedded_signatures(self, ctx: AnalysisContext) -> list[Indicator]:
        """Find known magic bytes elsewhere in the file (mini-binwalk).

        Catches payloads appended to or hidden inside images/PDFs/binaries
        (e.g. an exe after a PNG IEND or inside a PDF stream). Only runs on
        binary types; archives are already recursed, so their embedded
        containers are of no additional value here.
        """
        if ctx.detected_type in (
            "text", "html", "xml", "eml", "json", "lnk", "url", "empty", "ole",
            "zip", "rar", "7z", "tar", "gzip", "bzip2", "xz", "cab", "iso",
            "chm", "vhdx", "ntfs", "fat", "onenote",
        ):
            return []
        data = ctx.data
        if len(data) < 8:
            return []

        hits: list[tuple[str, int]] = []
        for label, magic, _severity, _weight in _EMBEDDED_SIGNATURES:
            if ctx.detected_type == "pe" and label == "pe":
                # A second PE inside a PE is the classic dropper/packer shape,
                # so "the file's own type" must NOT skip it (the old
                # `label == ctx.detected_type` check below silently disabled
                # PE-in-PE detection entirely). Search from offset 1 so the
                # file's own MZ at 0 is not counted, and require a structurally
                # valid PE header at the hit.
                pos = data.find(magic, 1)
                while pos != -1 and len(hits) < config.EMBEDDED_SIGNATURE_MAX:
                    if _pe_at(data, pos):
                        hits.append((label, pos))
                    pos = data.find(magic, pos + 1)
                continue
            if label == ctx.detected_type:
                continue  # the file's own signature at offset 0 is not a hit
            if ctx.detected_type == "pe" and label not in _EMBEDDED_IN_PE:
                continue  # icon resources legitimately embed PNG/GIF/…; only
                # archives/executables inside a PE are noteworthy
            pos = data.find(magic, 1)
            while pos != -1 and len(hits) < config.EMBEDDED_SIGNATURE_MAX:
                if label == "pe" and not _pe_at(data, pos):
                    pos = data.find(magic, pos + 1)
                    continue
                if label == "gzip" and not _gzip_header_ok(data, pos):
                    pos = data.find(magic, pos + 1)
                    continue
                if label == "cab" and not _cab_header_ok(data, pos):
                    pos = data.find(magic, pos + 1)
                    continue
                if label == "elf" and not _elf_at(data, pos):
                    pos = data.find(magic, pos + 1)
                    continue
                hits.append((label, pos))
                pos = data.find(magic, pos + 1)

        if not hits:
            return []
        # One finding per embedded TYPE, not per occurrence. Measured on 90
        # legitimate programs: repeated occurrences of the same 4-byte magic
        # inside compiled code added up to score 100 (tailscale.exe: eight
        # GEN_EMBEDDED findings from coincidental byte matches), which made the tool
        # report normal vendor software as malicious. The count is preserved
        # in the detail text; only the score contribution is aggregated.
        out: list[Indicator] = []
        by_label: dict[str, list[int]] = {}
        for label, offset in hits:
            by_label.setdefault(label, []).append(offset)
        for label, offsets in by_label.items():
            sev, weight = _EMBEDDED_LEVELS.get(label, (Severity.LOW, 5))
            if label in _WEAK_MAGIC:
                # Short magics (4 bytes) match inside ordinary machine code by
                # chance; only a hit that repeats many times is meaningful.
                if len(offsets) < 4:
                    continue
                sev, weight = Severity.LOW, 5
            if ctx.detected_type == "pe" and label in _ARCHIVE_LABELS:
                # MEASURED: an embedded ARCHIVE header is normal in compiled
                # software — Go/Rust binaries embed their debug/source ZIPs,
                # installers carry payload archives (17 of 90 legitimate
                # programs hit this, all pushed to YELLOW). An embedded
                # EXECUTABLE, by contrast, is the classic dropper shape and
                # stays fully weighted (it is structurally validated via
                # _pe_at above), so only archives are reduced to a note.
                sev, weight = Severity.INFO, 0
            where = ", ".join(str(o) for o in offsets[:5])
            more = f" (+{len(offsets) - 5} weitere)" if len(offsets) > 5 else ""
            out.append(
                self._indicator(
                    "GEN_EMBEDDED",
                    f"Eingebettete Signatur: {label} ({len(offsets)}x)",
                    detail=(
                        f"Der Dateikopf von {label} wurde {len(offsets)}x "
                        f"innerhalb der Datei gefunden (Offset {where}{more}) — "
                        "möglicher versteckter oder angehängter Inhalt."
                    ),
                    severity=sev,
                    category=CAT_SIGNATURE,
                    weight=weight,
                    source="generic",
                )
            )
        return out

    # -- content heuristics ------------------------------------------------ #

    def _content_checks(self, ctx: AnalysisContext) -> list[Indicator]:
        out: list[Indicator] = []
        if ctx.detected_type == "lnk":
            out.extend(self._lnk(ctx))
        if ctx.detected_type == "url":
            out.extend(self._internet_shortcut(ctx))
        if ctx.detected_type in _TEXT_CONTENT_TYPES:
            # Bound the heuristics to a leading sample: decoding/lowering and
            # the regex passes are O(n) each and would otherwise repeat dozens
            # of full scans over multi-megabyte files.
            sample = ctx.data[: config.MAX_CONTENT_SCAN_SIZE]
            if not sample:
                return out
            text = _decode_loose(sample)
            if text:
                sample_truncated = (
                    len(ctx.data) > config.MAX_CONTENT_SCAN_SIZE
                    or ctx.size > len(ctx.data)
                )
                deobf = self._run_script_deobf(
                    ctx, text, sample_truncated=sample_truncated
                )
                eval_text = text
                eval_bytes = sample
                if deobf is not None:
                    if deobf.changed or deobf.decoded_blobs:
                        extra_text = deobf.text + (
                            "\n" + "\n".join(deobf.decoded_blobs)
                            if deobf.decoded_blobs
                            else ""
                        )
                        eval_text = text + "\n" + extra_text
                        eval_bytes = (
                            sample
                            + b"\n"
                            + extra_text.encode("utf-8", errors="ignore")
                        )
                        uncovered = self._deobf_uncovered_hidden(
                            text, sample, eval_text, eval_bytes
                        )
                        if deobf.techniques and uncovered:
                            out.append(
                                self._indicator(
                                    "GEN_SCRIPT_DEOBFUSCATED",
                                    "Verschleiertes Skript statisch deobfuskiert",
                                    detail=(
                                        "Statische Deobfuskation (ohne Code-Ausführung) "
                                        "hat verborgene Befehle/IOCs freigelegt. Techniken: "
                                        + ", ".join(deobf.techniques[:8])
                                    ),
                                    severity=Severity.HIGH,
                                    category=CAT_SCRIPT,
                                    weight=30,
                                )
                            )
                        elif deobf.high_confidence_techniques:
                            out.append(
                                self._indicator(
                                    "GEN_SCRIPT_DEOBFUSCATED",
                                    "Verschleiertes Skript statisch deobfuskiert",
                                    detail=(
                                        "Deutliche Skript-Verschleierung statisch aufgelöst "
                                        "(ohne Code-Ausführung). Techniken: "
                                        + ", ".join(deobf.high_confidence_techniques[:8])
                                    ),
                                    severity=Severity.MEDIUM,
                                    category=CAT_SCRIPT,
                                    weight=15,
                                )
                            )
                    if deobf.limit_hit:
                        out.append(
                            self._indicator(
                                "GEN_DEOBF_LIMIT",
                                "Skript-Deobfuskation am Limit gestoppt",
                                detail=(
                                    f"Die statische Skript-Deobfuskation wurde am "
                                    f"Sicherheitslimit gestoppt ({deobf.limit_reason}). "
                                    "Verbleibender verschleierter Inhalt wurde nicht geprüft."
                                ),
                                severity=Severity.INFO,
                                category=CAT_SCRIPT,
                                weight=0,
                            )
                        )
                out.extend(self._suspicious_strings(eval_text))
                out.extend(self._powershell_analysis(eval_text))
                out.extend(self._iocs(ctx, eval_bytes))
                # The tail pass covers an appended payload (the classic append
                # trick). Only the region BEYOND the head sample is scanned:
                # `tail is not sample` was always True for byte slices and ran
                # the IOC regexes twice over identical data, duplicating
                # indicators and inflating the score.
                tail_size = config.MAX_CONTENT_TAIL_SIZE
                if tail_size > 0:
                    unsampled = ctx.data[config.MAX_CONTENT_SCAN_SIZE:]
                    if unsampled:
                        out.extend(self._iocs(ctx, unsampled[-tail_size:]))
                if (
                    ctx.detected_type == "unknown"
                    and shannon_entropy(sample) > config.IOC_MAX_ENTROPY
                ):
                    out.extend(self._binary_iocs(ctx))
        elif ctx.detected_type not in ("lnk", "url"):
            # Everything that is NOT decoded as text — PE/ELF/Mach-O, PDF, OLE,
            # images, archives, ISO, RTF, Java classes — had NO address check at
            # all, although that is exactly where a C2 address sits (data
            # section, XMP metadata, macro stream, appended payload). The
            # negative form is deliberate: a positive list of "binary" types
            # would silently go stale with every new magic signature, and the
            # address would be missed exactly where it stands.
            #
            # "lnk" is excluded: the LNK stage already evaluates its target and
            # argument strings, so a second pass over the same bytes would only
            # duplicate the finding.
            #
            # "url" is excluded for the same reason: the shortcut parser below
            # shows the target once, with its scheme/UNC/IP classification.
            out.extend(self._binary_iocs(ctx))
        return out

    def _binary_iocs(self, ctx: AnalysisContext) -> list[Indicator]:
        """Adressen in Formaten, die nicht als Text dekodiert werden.

        Kein doppelter Lauf zur Textprüfung: die greift nur für
        :data:`_TEXT_CONTENT_TYPES` und dieser Zweig nur für alles andere.
        """
        source = getattr(ctx, "source", None)
        if source is not None and source.size > len(ctx.data):
            hits = extract_binary_iocs_stream(
                source, deadline=getattr(ctx, "deadline", None)
            )
        else:
            hits = extract_binary_iocs(ctx.data)
        if not hits:
            return []
        blocked, plain, unavailable = split_blocked_iocs(hits)
        out: list[Indicator] = [
            self._blocklist_unavailable(rule_id, detail)
            for rule_id, detail in unavailable
        ]
        capped = capped_ioc_kinds(hits)
        if capped:
            labels = dict(_BINARY_IOC_LABELS)
            severity, weight = _BINARY_IOC_LEVELS["BINARY_IOC_CAPPED"]
            out.append(
                self._indicator(
                    "BINARY_IOC_CAPPED",
                    _BINARY_IOC_TITLES["BINARY_IOC_CAPPED"],
                    detail=(
                        "Der Trefferdeckel von "
                        f"{config.BINARY_IOC_MAX_HITS} Adressen je Art wurde "
                        "für folgende Arten erreicht: "
                        + ", ".join(labels.get(kind, kind) for kind in capped)
                        + ". Weitere Adressen dieser Arten wurden NICHT gegen "
                        "die lokalen Blocklisten geprüft — ein Blocklist-Treffer "
                        "kann daher fehlen."
                    ),
                    severity=severity,
                    category=CAT_IOC,
                    weight=weight,
                )
            )
        if blocked:
            severity, weight = _BINARY_IOC_LEVELS["BINARY_IOC_BLOCKED"]
            out.append(
                self._indicator(
                    "BINARY_IOC_BLOCKED",
                    f"{_BINARY_IOC_TITLES['BINARY_IOC_BLOCKED']} ({len(blocked)})",
                    detail=(
                        "Im Rohinhalt dieser Datei stehen Adressen, die auf "
                        "einer lokalen Blocklist stehen (Domains, IP-Netze "
                        "oder bekannte Schad-URLs). Geprüft wurde rein lokal: "
                        + _format_binary_iocs(blocked)
                    ),
                    severity=severity,
                    category=CAT_IOC,
                    weight=weight,
                )
            )
        if plain:
            severity, weight = _BINARY_IOC_LEVELS["BINARY_IOC"]
            qualifier = (
                "Ein Teil der lokalen Blocklisten war nicht lesbar; "
                "dieser Hinweis ist daher nicht vollständig."
                if unavailable
                else "Kein Eintrag auf einer lokalen Blocklist — Hinweis ohne Einfluss auf die Bewertung."
            )
            out.append(
                self._indicator(
                    "BINARY_IOC",
                    f"{_BINARY_IOC_TITLES['BINARY_IOC']} ({len(plain)})",
                    detail=(
                        "Serveradressen im Rohinhalt der Datei (kein Text, "
                        "deshalb nicht von der Textprüfung erfasst): "
                        + _format_binary_iocs(plain)
                        + ". "
                        + qualifier
                    ),
                    severity=severity,
                    category=CAT_IOC,
                    weight=weight,
                )
            )
        return out

    @staticmethod
    def _merge_deobf_results(
        first: ScriptDeobfResult, second: ScriptDeobfResult
    ) -> ScriptDeobfResult:
        merged = ScriptDeobfResult(
            text=second.text,
            changed=first.changed or second.changed,
            limit_hit=first.limit_hit or second.limit_hit,
            limit_reason=first.limit_reason or second.limit_reason,
        )
        for t in first.techniques:
            merged.add_technique(t, high_confidence=(t in first.high_confidence_techniques))
        for t in second.techniques:
            merged.add_technique(t, high_confidence=(t in second.high_confidence_techniques))
        seen_blobs: set[str] = set()
        for blob in (*first.decoded_blobs, *second.decoded_blobs):
            if blob not in seen_blobs:
                seen_blobs.add(blob)
                merged.decoded_blobs.append(blob)
        return merged

    def _run_script_deobf(
        self, ctx: AnalysisContext, text: str, *, sample_truncated: bool
    ) -> ScriptDeobfResult | None:
        ext = Path(ctx.path).suffix.lower()
        dtype = ctx.detected_type
        budget = DeobfBudget()
        explicit = False
        res: ScriptDeobfResult | None = None

        if ext in (".bat", ".cmd") or dtype == "batch":
            explicit = True
            r1 = deobfuscate_batch(text, explicit_script=True, budget=budget)
            r2 = deobfuscate_powershell(
                r1.text,
                explicit_script=True,
                budget=budget,
                charge_input=False,
                line_reset_single_quotes=True,
            )
            res = self._merge_deobf_results(r1, r2)
        elif ext in (".hta", ".wsf"):
            explicit = True
            r1 = deobfuscate_js_detailed(text, explicit_script=True, budget=budget)
            r2 = deobfuscate_powershell(
                r1.text,
                explicit_script=True,
                budget=budget,
                charge_input=False,
            )
            res = self._merge_deobf_results(r1, r2)
        elif ext in (".ps1", ".psm1", ".psd1") or dtype == "ps1":
            explicit = True
            res = deobfuscate_powershell(text, explicit_script=True, budget=budget)
        elif ext == ".vbs" or dtype == "vbs":
            explicit = True
            vba_strings = extract_vba_strings(text)
            res = deobfuscate_powershell(
                text,
                explicit_script=True,
                budget=budget,
                line_reset_single_quotes=True,
            )
            if vba_strings:
                for vs in vba_strings[:32]:
                    if vs not in res.decoded_blobs:
                        res.decoded_blobs.append(vs)
        elif ext in (".js", ".mjs", ".cjs") or dtype == "js":
            explicit = True
            res = deobfuscate_js_detailed(text, explicit_script=True, budget=budget)
        elif dtype in ("text", "unknown"):
            low = text[:65_536].lower()
            has_ps_ctx = (
                "powershell" in low
                or "invoke-expression" in low
                or "frombase64string" in low
                or "[char" in low
                or "-encodedcommand" in low
                or "-enc " in low
                or "downloadstring" in low
                or ("`" in low and ("new-object" in low or "i`ex" in low or "i`nv" in low))
            )
            has_bat_ctx = (
                "@echo" in low
                or (("cmd.exe" in low or "cmd /c" in low) and "^" in low)
                or ("set " in low and "%" in low and "^" in low)
            )
            if has_ps_ctx:
                res = deobfuscate_powershell(text, explicit_script=False, budget=budget)
            if has_bat_ctx:
                rb = deobfuscate_batch(
                    res.text if res is not None else text,
                    explicit_script=False,
                    budget=budget,
                    charge_input=(res is None),
                )
                res = self._merge_deobf_results(res, rb) if res is not None else rb

        if res is not None and explicit and sample_truncated:
            res.set_limit(REASON_INPUT_LIMIT)
        return res

    @staticmethod
    def _scan_signal_sets(
        text: str, raw: bytes
    ) -> tuple[set[str], bool, set[str], set[str], set[bytes]]:
        lowered = text.lower()
        tokens = {tok for tok in _SUSPICIOUS_TOKENS if tok in lowered}
        cradle = any(k in lowered for k in _PS_CRADLE_DOWNLOAD) and any(
            k in lowered for k in _PS_CRADLE_EXEC
        )
        lolbins: set[str] = set()
        for binary, args in _LOLBIN_ABUSE:
            if binary in lowered and any(a in lowered for a in args):
                lolbins.add(binary)
        enc_payloads = set(decode_powershell_encoded(text))
        iocs: set[bytes] = set()
        ioc_candidates: list[tuple[str, str]] = []
        for u in _collect(_URL_RE.finditer(raw), _not_benign_url, 16):
            u_str = _to_str(u)
            lf = classify_url(u_str, canonicalize=True)
            if lf is not None and (
                lf.is_shortener
                or lf.is_ip_literal
                or lf.is_punycode
                or lf.risky_tld
                or lf.has_credentials
            ):
                iocs.add(u.lower())
            ioc_candidates.append((IOC_URL, u_str))
        for ip in _collect(_IPV4_RE.finditer(raw), None, 16):
            ip_str = _to_str(ip)
            try:
                addr = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if not (addr.is_loopback or addr.is_unspecified):
                iocs.add(ip)
            ioc_candidates.append((IOC_IPV4, ip_str))
        for dom in _collect(_DOMAIN_RE.finditer(raw), _not_benign, 16):
            d_str = _to_str(dom)
            ioc_candidates.append((IOC_DOMAIN, d_str))
        if ioc_candidates:
            blocked, _plain, _unavail = split_blocked_iocs(ioc_candidates)
            for _kind, val in blocked:
                iocs.add(val.lower().encode("utf-8", errors="ignore"))
        return tokens, cradle, lolbins, enc_payloads, iocs

    @classmethod
    def _deobf_uncovered_hidden(
        cls, raw_text: str, raw_bytes: bytes, comb_text: str, comb_bytes: bytes
    ) -> bool:
        r_tok, r_cradle, r_lol, r_enc, r_ioc = cls._scan_signal_sets(
            raw_text, raw_bytes
        )
        c_tok, c_cradle, c_lol, c_enc, c_ioc = cls._scan_signal_sets(
            comb_text, comb_bytes
        )
        return bool(
            (c_tok - r_tok)
            or (c_cradle and not r_cradle)
            or (c_lol - r_lol)
            or (c_enc - r_enc)
            or (c_ioc - r_ioc)
        )

    def _suspicious_strings(self, text: str) -> list[Indicator]:
        lowered = text.lower()
        hits = sorted({tok for tok in _SUSPICIOUS_TOKENS if tok in lowered})
        if not hits:
            return []
        # Severity scales with the number of distinct suspicious tokens.
        severity = Severity.HIGH if len(hits) >= 2 else Severity.MEDIUM
        weight = 30 if len(hits) >= 2 else 15
        return [
            self._indicator(
                "GEN_SUSPICIOUS_STRINGS",
                f"Verdächtige Befehls-/LOLBin-Strings ({len(hits)})",
                detail=", ".join(hits[:12]),
                severity=severity,
                category=CAT_CONTENT,
                weight=weight,
            )
        ]

    def _powershell_analysis(self, text: str) -> list[Indicator]:
        """Deeper PowerShell / LOLBin heuristics (purely static).

        Decodes ``-EncodedCommand`` payloads and scans the cleartext, detects
        download cradles (fetch & run) and LOLBin abuse patterns (binary plus a
        characteristic abuse argument).
        """
        out: list[Indicator] = []
        lowered = text.lower()

        # 1) Encoded commands: decode the base64 payload, scan the cleartext.
        try:
            decoded_list = decode_powershell_encoded(text)
        except Exception:
            decoded_list = []
        if decoded_list:
            decoded_lower = "\n".join(decoded_list).lower()
            hidden = sorted({t for t in _SUSPICIOUS_TOKENS if t in decoded_lower})
            excerpt = decoded_list[0].strip()[: config.MAX_STRING_CAPTURE]
            out.append(
                self._indicator(
                    "GEN_PS_ENCODED",
                    f"Encodierter PowerShell-Befehl dekodiert ({len(decoded_list)})",
                    detail=(
                        "Ein -EncodedCommand-Payload wurde statisch dekodiert (nicht "
                        "ausgeführt). Klartext-Anfang: " + excerpt
                        + (" | Enthält: " + ", ".join(hidden[:8]) if hidden else "")
                    ),
                    severity=Severity.HIGH if hidden else Severity.MEDIUM,
                    category=CAT_CONTENT,
                    weight=30 if hidden else 15,
                )
            )

        # 2) Download cradle: fetch & run chain.
        dl = next((k for k in _PS_CRADLE_DOWNLOAD if k in lowered), None)
        ex = next((k for k in _PS_CRADLE_EXEC if k in lowered), None)
        if dl and ex:
            out.append(
                self._indicator(
                    "GEN_PS_CRADLE",
                    f"PowerShell-Download-Cradle ({dl} + {ex})",
                    detail="Download-Primitive kombiniert mit Ausführung (Fetch-&-Run).",
                    severity=Severity.HIGH,
                    category=CAT_CONTENT,
                    weight=30,
                )
            )

        # 3) LOLBin abuse: binary + characteristic abuse argument.
        abuse: list[str] = []
        for binary, args in _LOLBIN_ABUSE:
            if binary in lowered:
                arg = next((a for a in args if a in lowered), None)
                if arg:
                    abuse.append(f"{binary} {arg}")
        if abuse:
            out.append(
                self._indicator(
                    "GEN_LOLBIN_ABUSE",
                    f"LOLBin-Missbrauchsmuster ({len(abuse)})",
                    detail=", ".join(abuse[:8]),
                    severity=Severity.HIGH,
                    category=CAT_CONTENT,
                    weight=30,
                )
            )
        return out

    def _iocs(self, ctx: AnalysisContext, raw: bytes) -> list[Indicator]:
        # Random bytes in COMPRESSED data (packages, packed binaries) match
        # the domain regex as junk like "q.RU" or "p0g9.Pw" — live field
        # report. String extraction only means something on mostly-textual
        # content; near-maximal entropy means "no readable strings at all".
        if shannon_entropy(ctx.data) >= config.IOC_MAX_ENTROPY:
            return []
        # finditer + early stop: a crafted file can contain millions of minimal
        # URLs/IPs; materialising all matches first would amplify memory.
        urls = _collect(_URL_RE.finditer(raw), _not_benign_url, 8)
        ips = _collect(_IPV4_RE.finditer(raw), None, 8)
        domains = _collect(_DOMAIN_RE.finditer(raw), _not_benign, 8)
        if not (urls or ips or domains):
            return []
        lines = []
        if urls:
            lines.append("URLs: " + ", ".join(_to_str(u) for u in urls))
        if ips:
            lines.append("IPv4: " + ", ".join(_to_str(i) for i in ips))
        if domains:
            lines.append("Domains: " + ", ".join(_to_str(d) for d in domains))
        return [
            self._indicator(
                "GEN_IOC",
                f"Extrahierte IOCs ({len(urls)} URL, {len(ips)} IP, {len(domains)} Domain)",
                detail=" | ".join(lines),
                # KEIN GEWICHT: das ist eine AUFLISTUNG, kein Befund. Die Regel
                # sagt "diese Adressen stehen in der Datei", nicht "diese Datei
                # ist auffaellig" — und sie laeuft PRO MITGLIED. GEMESSEN: eine
                # legitime Praesentation ueber Apache-Performance (aus den
                # Testdaten von Apache POI) enthaelt in ihren Folien viele URLs
                # und IP-Adressen; 12 Mitglieder x 5 Punkte ergaben 60 und
                # damit ROT. Der Nutzer will die Adressen SEHEN, nicht dafuer
                # bestraft werden, dass sie da sind.
                #
                # Ob eine Adresse boese ist, entscheidet die Reputation
                # (MAIL_LINK_REPUTATION, lokale Listen) — dafuer gibt es sie.
                severity=Severity.INFO,
                category=CAT_IOC,
                weight=0,
            )
        ]

    def _internet_shortcut(self, ctx: AnalysisContext) -> list[Indicator]:
        """Parse a Windows .url shortcut (INI) without following its target.

        The file is text, so the generic binary pass is deliberately skipped
        for this type (see ``_content_checks``): the target is shown exactly
        once, defanged, and its dangerous properties are named. Nothing is
        opened, resolved or executed — a ``file:``/UNC/``javascript:`` target
        only produces a finding.
        """
        values = _parse_shortcut_values(ctx.data[: config.MAX_CONTENT_SCAN_SIZE])
        target = values.get("url", "").strip()
        if not target:
            return []
        shown = defang_url(target[:512])
        extras = []
        if values.get("iconfile"):
            extras.append("IconFile=" + values["iconfile"][:200])
        if values.get("hotkey"):
            extras.append("HotKey=" + values["hotkey"][:80])
        out = [
            self._indicator(
                "URL_SHORTCUT_TARGET",
                "Internet-Verknüpfung: Ziel extrahiert",
                detail="Ziel: " + shown + ((" | " + " | ".join(extras)) if extras else ""),
                severity=Severity.INFO,
                category=CAT_CONTENT,
                weight=0,
            )
        ]
        reasons = _shortcut_reasons(target)
        if reasons:
            out.append(
                self._indicator(
                    "URL_SHORTCUT_SUSPICIOUS",
                    "Internet-Verknüpfung mit verdächtigem Ziel",
                    detail=(
                        ", ".join(reasons)
                        + ". Die Datei wird nicht geöffnet und das Ziel "
                        "nicht aufgelöst."
                    ),
                    # 25, nicht 15: ein .url ist eine einzelne, winzige Datei;
                    # ein Verweis auf eine lokale EXE, eine UNC-Freigabe oder
                    # ein javascript:-Ziel ist dann das EINZIGE Signal. Bei
                    # 15 bliebe genau dieser Fall GRÜN. Die Fixtures
                    # (url_file/url_unc/url_javascript/url_ip/url_credentials
                    # gegen url_benign) sind die Kalibrierung: bösartig -> GELB,
                    # Intranet-Ziel -> GRÜN.
                    #
                    # Bewusst NICHT auf 0 gesetzt: die YARA-Methodology-Regeln
                    # für .url liegen in signature_base, einem OPTIONALEN
                    # Nutzer-Download. Der Snapshot/die CI prüfen nur die
                    # mitgelieferten Regeln; ohne signature_base wäre ein
                    # lokales EXE-Ziel sonst GRÜN. Ist signature_base
                    # installiert, kann YARA zusätzlich 30 geben (dann ROT) —
                    # das ist die dokumentierte Wirkung zusätzlicher Threat-
                    # Intel, kein Doppelzählen derselben mitgelieferten Regel.
                    severity=Severity.MEDIUM,
                    category=CAT_CONTENT,
                    weight=25,
                )
            )
        return out

    def _lnk(self, ctx: AnalysisContext) -> list[Indicator]:
        info = parse_lnk(ctx.data)
        if not info.valid:
            return []
        out: list[Indicator] = []
        strings = info.interesting_strings()
        if strings:
            out.append(
                self._indicator(
                    "LNK_STRINGS",
                    "Shell-Link (.lnk) Ziele/Argumente extrahiert",
                    detail=" | ".join(strings),
                    severity=Severity.INFO,
                    category=CAT_CONTENT,
                    weight=0,
                )
            )
        # The dangerous pattern: a shortcut carrying command-line arguments,
        # especially invoking a shell/LOLBin.
        if info.has_arguments:
            arg_lower = info.arguments.lower()
            target_lower = (info.relative_path or "").lower()
            shell = any(
                t in arg_lower or t in target_lower
                for t in ("cmd", "powershell", "wscript", "cscript", "mshta", "rundll32")
            )
            out.append(
                self._indicator(
                    "LNK_ARGUMENTS",
                    "Shell-Link mit Kommandozeilen-Argumenten",
                    detail=(
                        f"Argumente: {info.arguments}"
                        + (" | Ziel: " + info.relative_path if info.relative_path else "")
                    ),
                    severity=Severity.HIGH if shell else Severity.MEDIUM,
                    category=CAT_CONTENT,
                    weight=30 if shell else 15,
                )
            )
        return out


# -- small helpers --------------------------------------------------------- #


def _parse_shortcut_values(raw: bytes) -> dict[str, str]:
    """INI key/value pairs of a .url file (keys lowercased, bounded by caller)."""
    values: dict[str, str] = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line or line[0] in ";#":
            continue
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip().lower()] = value.strip()
    return values


def _shortcut_reasons(target: str) -> list[str]:
    """Dangerous properties of a shortcut target (never resolves it)."""
    reasons: list[str] = []
    lowered = target.lower()
    scheme = ""
    if ":" in lowered and not lowered.startswith(("\\\\", "//")):
        scheme = lowered.split(":", 1)[0]
    if scheme in ("javascript", "vbscript", "data"):
        reasons.append(f"{scheme}:-Schema (führt Code aus)")
    if scheme == "file":
        reasons.append("file:-Schema (lokales Ziel)")
    # A bare Windows path (C:\..., C:/...) is the same local-target shape as
    # file: and is not recognised as a URL scheme by urlsplit.
    if (
        len(lowered) > 2
        and lowered[0].isalpha()
        and lowered[1] == ":"
        and lowered[2] in ("\\", "/")
    ):
        reasons.append("Lokaler Laufwerkspfad")
    if lowered.startswith(("\\\\", "//")):
        reasons.append("UNC-Pfad (Netzwerkfreigabe)")
    try:
        split = urlsplit(target)
        host = split.hostname or ""
        if split.netloc and "@" in split.netloc:
            reasons.append("Zugangsdaten in der URL")
        if (
            scheme == "file"
            and split.netloc
            and split.netloc.lower() != "localhost"
            and "UNC-Pfad (Netzwerkfreigabe)" not in reasons
        ):
            reasons.append("UNC-Pfad (Netzwerkfreigabe)")
        if host:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                reasons.append("IP-Adresse als Ziel")
    except ValueError:
        # Malformed IPv6 brackets etc.: not itself a reason list entry.
        pass
    return reasons


def _decode_loose(data: bytes) -> str:
    """Best-effort decode of a text-ish blob for heuristics (never raises).

    The only caller passes data already capped at MAX_CONTENT_SCAN_SIZE,
    so no second cap is applied here.
    """
    if not data:
        return ""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="ignore")
    return data.decode("utf-8", errors="ignore")


def _collect(matches, keep, limit: int) -> list[bytes]:
    """Dedupe regex match values lazily with an early stop.

    Iterates a ``finditer`` iterator and stops as soon as ``limit`` unique
    (case-insensitive) values are collected. This avoids materialising the full
    match list first — a crafted file can contain millions of minimal matches.
    ``keep`` is an optional predicate; values failing it are skipped.
    """
    seen: set[bytes] = set()
    out: list[bytes] = []
    for m in matches:
        item = m.group(0)
        if keep is not None and not keep(item):
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def _to_str(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def _format_binary_iocs(hits: list[tuple[str, str]], limit: int = 8) -> str:
    """Treffer als ``URLs: … | IPv4: … | Domains: …``.

    Je Art höchstens ``limit`` Werte; die Restzahl steht in Klammern, damit ein
    präpariertes File mit hunderten Adressen den Befundtext nicht flutet.
    """
    parts: list[str] = []
    for kind, label in _BINARY_IOC_LABELS:
        values = [value for hit_kind, value in hits if hit_kind == kind]
        if not values:
            continue
        more = f" (+{len(values) - limit} weitere)" if len(values) > limit else ""
        parts.append(f"{label}: {', '.join(values[:limit])}{more}")
    return " | ".join(parts)


def _not_benign(domain: bytes) -> bool:
    low = domain.lower().decode("utf-8", errors="replace")
    return not any(low == h or low.endswith("." + h) for h in _BENIGN_HOSTS)


def _host_of_url(url: bytes) -> bytes:
    """Extract the host portion of an http(s) URL (no scheme, no port, no path)."""
    rest = url.split(b"://", 1)[1] if b"://" in url else url
    host = rest.split(b"/", 1)[0].split(b"?", 1)[0].split(b"#", 1)[0]
    # Strip a trailing ":port".
    if b":" in host:
        host = host.rsplit(b":", 1)[0]
    return host.strip().lower()


def _not_benign_url(url: bytes) -> bool:
    return _not_benign(_host_of_url(url))


# -- embedded signature scan ------------------------------------------------ #
#
# (label, magic, severity, weight) — magics are >= 4 bytes to keep random
# binary noise out; PE is validated structurally before it counts as a hit.
_EMBEDDED_SIGNATURES = (
    ("pe", b"MZ", Severity.HIGH, 30),
    ("elf", b"\x7fELF", Severity.HIGH, 30),
    ("zip", b"PK\x03\x04", Severity.MEDIUM, 15),
    ("rar", b"Rar!\x1a\x07", Severity.MEDIUM, 15),
    ("7z", b"7z\xbc\xaf\x27\x1c", Severity.MEDIUM, 15),
    ("gzip", b"\x1f\x8b", Severity.MEDIUM, 15),
    ("cab", b"MSCF", Severity.MEDIUM, 15),
    ("pdf", b"%PDF-", Severity.LOW, 5),
    ("ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", Severity.LOW, 5),
    ("png", b"\x89PNG\r\n\x1a\n", Severity.LOW, 5),
    ("gif", b"GIF87a", Severity.LOW, 5),
    ("gif", b"GIF89a", Severity.LOW, 5),
    ("class", b"\xca\xfe\xba\xbe", Severity.LOW, 5),
    ("macho", b"\xfe\xed\xfa\xce", Severity.LOW, 5),
)

_EMBEDDED_LEVELS = {
    label: (severity, weight) for label, _m, severity, weight in _EMBEDDED_SIGNATURES
}

# Labels worth reporting when found *inside* a PE (icons make image/office
# magics common and legitimate there).
_EMBEDDED_IN_PE = frozenset({"elf", "zip", "rar", "7z", "gzip", "cab"})

# Archive labels: embedded archive headers are routine in compiled software
# (Go debug ZIPs, installer payloads), so inside a PE they are reported as a
# note. Executables are NOT in this set — a second PE is a dropper.
_ARCHIVE_LABELS = frozenset({"zip", "rar", "7z", "gzip", "cab"})

# Magics of four bytes or less: they occur inside ordinary machine code by
# chance (measured: "MSCF" in urlmon.dll). A single coincidental match is not
# evidence — BUT only where no structural validation exists to tell a real
# embedding from noise. gzip and cab already have one (_gzip_header_ok /
# _cab_header_ok), so for them a single validated hit is meaningful and the
# repetition rule would suppress genuine findings (regression caught by
# test_embedded_gzip_requires_plausible_header). Only "rar" and "zip" have no
# validator, so they are the ones needing corroboration by repetition.
_WEAK_MAGIC = frozenset({"rar", "zip"})


def _gzip_header_ok(data: bytes, pos: int) -> bool:
    """True when ``data[pos:]`` starts with a plausible gzip header.

    Random bytes often contain the 2-byte magic; requiring the deflate method
    (0x08) and clear reserved flag bits removes nearly all coincidental hits.
    """
    if len(data) < pos + 4:
        return False
    return data[pos + 2] == 0x08 and (data[pos + 3] & 0xE0) == 0


def _elf_at(data: bytes, pos: int) -> bool:
    """True when ``data[pos:]`` starts with a plausible ELF header.

    ``\\x7fELF`` is only four bytes and occurs inside ordinary machine code
    (measured: Microsoft's SenseTVM.exe has a coincidental hit mid-instruction).
    A real ELF continues with a 64-bit class, a data-encoding byte, an
    OS-ABI/version pair and a zero-padded e_ident tail.
    """
    if len(data) < pos + 16:
        return False
    ei_class = data[pos + 4]
    ei_data = data[pos + 5]
    if ei_class not in (1, 2):          # ELFCLASS32 / ELFCLASS64
        return False
    if ei_data not in (1, 2):           # little / big endian
        return False
    if data[pos + 6] != 1:              # EI_VERSION must be EV_CURRENT
        return False
    # Bytes 9..15 of e_ident are padding and must be zero.
    return data[pos + 9 : pos + 16] == b"\x00" * 7


def _cab_header_ok(data: bytes, pos: int) -> bool:
    """True when ``data[pos:]`` starts with a plausible Microsoft CAB header.

    "MSCF" is only four bytes, so code data contains it by chance (measured:
    urlmon.dll has one such hit in the middle of ordinary instructions). A real
    CAB carries the full header layout below — verified against real CAB files
    on this system (Windows\\appcompat\\cloudsdb.cab, CBS logs), not just the
    spec: reserved1/2/3 are zero, versionMajor is 1 or 3, and folder/file
    counts are non-zero.

    Byte layout (MS-CAB spec):
        0  "MSCF" | 4 reserved1 | 8 cbCabinet | 12 reserved2 | 16 coffFiles
        20 reserved3 | 24 versionMinor | 25 versionMajor | 26 cFolders
        28 cFiles | 30 flags | 32 setID | 34 iCabinet
    """
    if len(data) < pos + 36:
        return False
    reserved1, cb_cabinet, reserved2, _coff_files, reserved3 = struct.unpack_from(
        "<IIIII", data, pos + 4
    )
    version_major = data[pos + 25]
    c_folders, c_files = struct.unpack_from("<HH", data, pos + 26)
    return (
        reserved1 == 0
        and reserved2 == 0
        and reserved3 == 0
        and cb_cabinet > 0
        and version_major in (1, 3)
        and c_folders >= 1
        and c_files >= 1
    )


def _pe_at(data: bytes, pos: int) -> bool:
    """True when ``data[pos:]`` starts with a structurally valid PE header."""
    if len(data) < pos + 0x40 or data[pos : pos + 2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(data[pos + 0x3C : pos + 0x40], "little")
    if e_lfanew <= 0 or pos + e_lfanew + 4 > len(data):
        return False
    return data[pos + e_lfanew : pos + e_lfanew + 4] == b"PE\x00\x00"
