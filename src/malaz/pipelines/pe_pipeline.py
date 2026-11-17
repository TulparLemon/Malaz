"""PE (Windows executable) analysis pipeline.

Until now PE files only received the generic surface checks (entropy, YARA).
This pipeline adds the classic static-forensics signals:

1. Structure — sections (names, raw/virtual sizes, per-section entropy), machine
   type, TLS callbacks, debug/PDB info, overlay data.
2. Imports — suspicious API combinations (process injection, download & exec,
   keylogging) and the imphash fingerprint.
3. Mitigations — missing ASLR/DEP flags (weak hardening).
4. Authenticode — signature validity via Windows PowerShell
   (``Get-AuthenticodeSignature``, fully local, Windows only).
5. Detect It Easy — optional external engine for packer/compiler/protector
   identification (MIT, not bundled; format identification only, never
   malware-family verdicts).
6. capa — optional external engine that names CAPABILITIES in whole sentences
   ("persist via Run key"), i.e. what the program CAN do (Apache-2.0, not
   bundled; capability names only, never a malware-family verdict).

Every stage degrades gracefully: a missing library/engine or an unparseable
file yields informational indicators, never a crash.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from functools import lru_cache
from pathlib import Path

from .. import config
from ..analysis.capa import CapaResult, CapaScanner, _capa_disabled_hint
from ..analysis.die import DieScanner, finding_risk
from ..core.entropy import shannon_entropy
from ..core.strings_extract import SectionSpan, StringsResult, extract_strings
from ..core.suspicious_tokens import SUSPICIOUS_COMMAND_TOKENS
from ..core.toolpath import which_absolute
from ..models import (
    CAT_CONTENT,
    CAT_FORMAT,
    CAT_RESOURCE,
    CAT_SIGNATURE,
    CAT_STRUCTURE,
    AnalysisContext,
    Indicator,
    Severity,
)
from ..procio import (
    decode_tool_output,
    run_tool,
    safe_temp_suffix,
    tool_output_truncated,
)
from .base import Pipeline

# Section names that scream "packer/protector" (UPX, MPRESS, VMProtect, …).
_PACKER_SECTION_NAMES = (
    b"upx0", b"upx1", b"upx2", b".aspack", b".adata", b".mpress1", b".mpress2",
    b".nsp0", b".nsp1", b".petite", b".sforce3", b".vmp0", b".vmp1",
    b".themida", b".enigma1", b".enigma2", b".ccg", b".pinclie",
)

# Section names that legitimately carry NO raw data: uninitialised data
# (.bss), thread-local storage (.tls), debug info (.debug), and linker
# bookkeeping. Toolchains emit them as "raw size 0, virtual size > 0" by
# design, so that layout alone is not a packer signal.
_NORMAL_ZERO_RAW_SECTIONS = frozenset(
    {b"bss", b"tls", b"debug", b"drectve", b"crt", b"ctors", b"dtors"}
)

# Suspicious import combinations. Each entry is (rule_id, label, groups);
# a pattern fires when every group has at least one imported function.
_IMPORT_PATTERNS = (
    (
        # Process injection needs a COMBINATION, not a single API. The matcher
        # requires one hit per group (AND across groups, OR within), so the
        # triad is expressed as THREE groups: reserve memory (VirtualAllocEx),
        # write into it (WriteProcessMemory) and start execution remotely
        # (CreateRemoteThread family).
        #
        # HONEST CALIBRATION: even the full triad is NOT a reliable signal —
        # measured on legitimate software, firefox.exe imports exactly this
        # combination (plugin sandboxing / process isolation). Import lists
        # alone cannot separate that from a malicious loader, so the weight
        # reflects "worth a look", not "likely malicious". The decisive
        # evidence comes from behaviour/YARA/AV, not from the import table.
        "PE_IMPORT_INJECTION",
        "Prozess-Injektions-APIs",
        (
            ("virtualallocex", "ntallocatevirtualmemory"),
            ("writeprocessmemory", "ntwritevirtualmemory"),
            (
                "createremotethread",
                "ntcreatethreadex",
                "queueuserapc",
                "setthreadcontext",
                "rtlcreateuserthread",
            ),
        ),
    ),
    (
        "PE_IMPORT_DOWNLOAD_EXEC",
        "Download-&-Execute-APIs",
        (
            ("urldownloadtofilea", "urldownloadtofilew"),
            ("winexec", "shellexecutea", "shellexecutew", "shellexecuteexa",
             "shellexecuteexw", "createprocessa", "createprocessw", "createprocessasuserw"),
        ),
    ),
    (
        "PE_IMPORT_KEYLOG",
        "Keylogger-APIs",
        (
            ("setwindowshookexa", "setwindowshookexw"),
            ("getasynckeystate", "getkeystate"),
        ),
    ),
)

# Calibrated weights for the import combinations above. Measured base rates on
# legitimate software: KEYLOG fires on software with global hotkeys, INJECTION
# on software that isolates plugins (firefox.exe), so neither justifies a high
# weight on its own. DOWNLOAD_EXEC is the most specific of the three.
_IMPORT_WEIGHTS = {
    "PE_IMPORT_INJECTION": (Severity.LOW, 5),
    "PE_IMPORT_KEYLOG": (Severity.LOW, 5),
    "PE_IMPORT_DOWNLOAD_EXEC": (Severity.MEDIUM, 15),
}

# AP9: command-shaped strings inside a PE. Deliberately NO addresses here —
# those stay the job of ``binary_iocs`` (one cause, one statement). Both rules
# start at weight 0: the extraction is a foundation, not a calibrated
# detection, so no score may move without a fixture + counterexample review.
# The vocabulary itself is shared with the generic text stage.
_PE_SUSPICIOUS_DETAIL_LIMIT = 8

# AP10: resource/manifest/version/Rich metadata. Everything here is a report
# fact with weight 0 — none of it is calibrated as a malware signal.
_VERSION_FIELDS = (
    "CompanyName",
    "ProductName",
    "FileDescription",
    "OriginalFilename",
    "InternalName",
    "LegalCopyright",
)
_MANIFEST_LEVEL = re.compile(
    r"requestedExecutionLevel[^>]*level\s*=\s*\"([^\"]+)\"", re.IGNORECASE
)
_MANIFEST_UI_ACCESS = re.compile(
    r"uiAccess\s*=\s*\"([^\"]+)\"", re.IGNORECASE
)
_MANIFEST_AUTO_ELEVATE = re.compile(
    r"<autoElevate>\s*(true|false)\s*</autoElevate>", re.IGNORECASE
)
_MANIFEST_MAX_BYTES = 64 * 1024
_RICH_SIGNATURE = 0x536E6144  # "DanS"
_RICH_MAX_ENTRIES = 64
_RESOURCE_NAME_MAX = 60
_RESOURCE_DETAIL_MAX = 2000

# Arbeitsbudget der Sektionsanalyse (SEC-020): 2048 Sektionen à 64 MiB
# ergaben ~10 Minuten CPU für EINE Datei. Der Deckel begrenzt Anzahl und
# Bytes je Sektion; ein sichtbarer Befund nennt die Kürzung.
_SECTION_ENTROPY_MAX_SECTIONS = 96
_SECTION_ENTROPY_MAX_BYTES = 1 * 1024 * 1024
# PDB-Namen sind angreiferkontrolliert (SEC-019): pefile erlaubt bis zu 2048
# Debug-Einträge mit sehr langen Namen. Gekappt wird Anzahl UND Länge.
_PDB_MAX_ENTRIES = 16
_PDB_NAME_MAX = 512


def _suspicious_string_hits(result: StringsResult) -> tuple[list[str], list[str]]:
    """Return ``(tokens, examples)`` for command-shaped strings, in file order.

    Address-shaped strings are deliberately NOT matched here: ``binary_iocs``
    already reports URLs/IPs/domains once. Matching a token twice would
    double-report the same bytes.
    """
    tokens: list[str] = []
    examples: list[str] = []
    needles = SUSPICIOUS_COMMAND_TOKENS
    for entry in result.strings:
        lowered = entry.value.lower()
        matched = [text for text in needles if text in lowered]
        if not matched:
            continue
        for text in matched:
            if text not in tokens:
                tokens.append(text)
        if len(examples) < 3:
            section = entry.section or "außerhalb"
            examples.append(
                f"{section} @ Datei-Offset 0x{entry.offset:x}: {entry.value[:120]}"
            )
    return tokens, examples


def _resource_entry_name(entry) -> str:
    """Human name of a resource directory entry (named or numeric)."""
    name = getattr(entry, "name", None)
    text = getattr(name, "string", None) if name is not None else None
    if text:
        return text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
    return str(getattr(entry, "id", "?"))


def _resource_data(pe, type_id: int, name_id: int | None) -> bytes | None:
    """First data blob for ``RT_<type_id>`` (optionally a specific name).

    ``name_id=None`` accepts every name entry: application manifests are
    usually ID 1, but DLLs legitimately carry them under IDs 2/3 or a name.
    """
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return None
    for type_entry in getattr(root, "entries", []) or []:
        if getattr(type_entry, "id", None) != type_id:
            continue
        for name_entry in getattr(type_entry.directory, "entries", []) or []:
            if name_id is not None and getattr(name_entry, "id", None) != name_id:
                continue
            for lang_entry in getattr(name_entry.directory, "entries", []) or []:
                data_struct = getattr(getattr(lang_entry, "data", None), "struct", None)
                if data_struct is None:
                    continue
                try:
                    size = min(int(data_struct.Size), _MANIFEST_MAX_BYTES)
                    return pe.get_data(data_struct.OffsetToData, size)
                except Exception:
                    return None
    return None


def _pdb_paths(pe) -> tuple[list[str], int, int]:
    """Bounded ``(paths, dropped_entries, clipped_names)`` from debug data.

    SEC-019: pefile accepts up to 2048 debug entries and the PDB name is
    attacker-controlled. Both count and length are capped before anything is
    decoded into a report string; the caller surfaces the truncation.
    """
    paths: list[str] = []
    dropped = 0
    clipped = 0
    for index, entry in enumerate(
        getattr(pe, "DIRECTORY_ENTRY_DEBUG", None) or []
    ):
        if index >= _PDB_MAX_ENTRIES:
            dropped += 1
            continue
        pdb = getattr(getattr(entry, "entry", None), "PdbFileName", None)
        if not pdb:
            continue
        if isinstance(pdb, bytes):
            if len(pdb) > _PDB_NAME_MAX:
                clipped += 1
                pdb = pdb[:_PDB_NAME_MAX]
            text = pdb.decode("latin-1", "replace").rstrip("\x00")
        else:
            text = str(pdb)
            if len(text) > _PDB_NAME_MAX:
                clipped += 1
                text = text[:_PDB_NAME_MAX] + "…"
        paths.append(text)
    return paths, dropped, clipped


def _manifest_facts(blob: bytes) -> dict[str, str]:
    """Requested elevation facts from an embedded application manifest."""
    text = blob.decode("utf-8", "replace")
    level = _MANIFEST_LEVEL.search(text)
    ui_access = _MANIFEST_UI_ACCESS.search(text)
    auto_elevate = _MANIFEST_AUTO_ELEVATE.search(text)
    facts: dict[str, str] = {}
    if level:
        facts["level"] = level.group(1)
    if ui_access:
        facts["uiAccess"] = ui_access.group(1)
    if auto_elevate:
        facts["autoElevate"] = auto_elevate.group(1)
    return facts


def _version_strings(pe) -> dict[str, str]:
    """Selected VS_VERSIONINFO fields, bounded and deduplicated."""
    out: dict[str, str] = {}
    for group in getattr(pe, "FileInfo", []) or []:
        for info in group:
            for table in getattr(info, "StringTable", []) or []:
                entries = getattr(table, "entries", None)
                if not isinstance(entries, dict):
                    continue
                for key, value in entries.items():
                    name = (
                        key.decode("utf-8", "replace")
                        if isinstance(key, bytes)
                        else str(key)
                    )
                    if name not in _VERSION_FIELDS or name in out:
                        continue
                    text = (
                        value.decode("utf-8", "replace")
                        if isinstance(value, bytes)
                        else str(value)
                    )
                    if text:
                        out[name] = text[:200]
    return out


def _rich_header(data: bytes, pe_offset: int) -> tuple[int, list[tuple[int, int]]] | None:
    """Decode the Rich header (XOR key + compiler build entries), bounded.

    Layout: ``DanS`` + three key DWORDs + ``(compid, count)`` pairs + ``Rich``
    + key. The XOR key is stored after ``Rich``; all other DWORDs are XORed
    with it. A malformed/absent header returns ``None`` — never a guess.
    """
    limit = min(pe_offset if pe_offset > 0 else len(data), len(data))
    rich = data.rfind(b"Rich", 0x40, limit)
    if rich < 0 or rich + 8 > len(data):
        return None
    key = int.from_bytes(data[rich + 4 : rich + 8], "little")
    start = None
    for pos in range(rich - 8, 0x3F, -4):
        if (int.from_bytes(data[pos : pos + 4], "little") ^ key) == _RICH_SIGNATURE:
            start = pos
            break
    if start is None or start + 16 > rich:
        return None
    entries: list[tuple[int, int]] = []
    pos = start + 16
    while pos + 8 <= rich and len(entries) < _RICH_MAX_ENTRIES:
        compid = int.from_bytes(data[pos : pos + 4], "little") ^ key
        count = int.from_bytes(data[pos + 4 : pos + 8], "little") ^ key
        entries.append((compid, count))
        pos += 8
    return key, entries


# Severity/weight and title of the capa rules. Kept in tables for the same
# reason as the import weights: a new rule id has to show up here, it must not
# quietly fall back to a default (tests/test_capa.py checks both tables).
#
# CAPA_CAPABILITY: LOW/5. Die Regelbasis feuert auf fast jedem Programm, und
# das ist GEMESSEN (Standalone-capa 9.4.0, harmlose Alltagsbibliotheken):
#
#     libffi-8.dll      5 Faehigkeiten   (u.a. "allocate or change RWX memory")
#     msvcp140.dll     18 Faehigkeiten
#     libssl-3.dll      8 Faehigkeiten
#
# Ein Signal, das fuer praktisch jede EXE gilt, darf sie nicht ueber die
# Schwelle heben — dieselbe Regel wie bei MAIL_AUTH_ABSENT (5) und beim
# Zaehlpixel. capa ist eine Ausrichtung ("was KANN das"), kein Urteil; das
# entscheidende Gewicht gehoert YARA/AV/Heuristik.
#
# Der vorige Kommentar behauptete hier "measured against legitimate software"
# und setzte trotzdem MEDIUM/15 — die Behauptung war zu diesem Zeitpunkt
# unbelegt (capa war nicht installiert). Jetzt ist sie es.
# CAPA_UNAVAILABLE: pure diagnosis of the engine configuration (capa missing),
# deliberately weight 0 — the other stages stay untouched.
_CAPA_LEVELS = {
    # LOW/5, nicht MEDIUM/15: die Regelbasis meldet auf fast jedem Programm
    # Faehigkeiten wie "Prozess starten" oder "Datei lesen". Ein Signal, das
    # fuer praktisch jede EXE gilt, darf sie nicht ueber die Schwelle heben —
    # dieselbe Regel wie bei MAIL_AUTH_ABSENT (5) und beim Zaehlpixel.
    #
    # NICHT GEMESSEN: capa ist auf diesem Rechner nicht installiert, ein
    # Gegenbeweis an echten Programmen steht daher aus. Die Entscheidung
    # stuetzt sich auf die dokumentierte Breite der Regelbasis; sobald capa
    # verfuegbar ist, gehoert die Messung nachgeholt.
    "CAPA_CAPABILITY": (Severity.LOW, 5),
    "CAPA_UNAVAILABLE": (Severity.INFO, 0),
    # Materialising the temp file can fail (path/disk); without a report the
    # whole stage would vanish silently — same reason DIE_ERROR exists.
    "CAPA_ERROR": (Severity.INFO, 0),
    # Die Stufe lief gar nicht (Regelbasis fehlt, Timeout, Uebergroesse).
    # Ebenfalls Diagnose — aber SICHTBAR, sonst liest der Nutzer das Fehlen
    # der Zeile als "nichts gefunden".
    "CAPA_SKIPPED": (Severity.INFO, 0),
}

_CAPA_TITLES = {
    "CAPA_SKIPPED": "capa konnte nicht laufen",
    "CAPA_CAPABILITY": "capa: Fähigkeiten erkannt",
    "CAPA_UNAVAILABLE": "capa nicht installiert",
    "CAPA_ERROR": "capa-Analyse fehlgeschlagen",
}

# How many capabilities are named in the DETAIL text. A packed/hostile sample
# can match hundreds of rules; the report stays readable by naming the first
# few and summarising the rest ("… und N weitere"). The count is preserved
# either way — the truncation never pretends there was less.
_CAPA_DETAIL_LIMIT = 8


def _capa_detail(result: CapaResult) -> str:
    """Detail text for CAPA_CAPABILITY: German capability names, capped."""
    names = [rule.display for rule in result.capabilities]
    shown = "; ".join(names[:_CAPA_DETAIL_LIMIT])
    rest = len(names) - _CAPA_DETAIL_LIMIT
    if rest > 0:
        shown += f"; … und {rest} weitere"
    detail = (
        f"capa erkennt {len(names)} Fähigkeiten "
        "(Fähigkeits-Analyse, keine Bewertung als Schadsoftware): "
        f"{shown}"
    )
    if result.truncated:
        detail += (
            f" (capa meldete mehr als {len(names)} Regeln; "
            "die Liste ist gekappt)"
        )
    return detail


# DllCharacteristics bits (IMAGE_DLLCHARACTERISTICS_*).
# DER-OID 1.2.840.113549.1.1.1 (rsaEncryption) — steht am Anfang jeder
# PKCS#7-Signatur und identifiziert einen angehängten Authenticode-Blob.
_PKCS7_OID = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d"

# Get-AuthenticodeSignature-Status, die eine zum Dateiinhalt passende Signatur
# belegen. ``Valid`` = Kette vertrauenswürdig, ``NotTrusted`` = Signatur passt,
# nur die Kette ist es nicht (die Vertrauensfrage meldet PE_SIGNATURE_UNTRUSTED
# separat). Alles andere — insbesondere ``NotSigned`` (gar keine Signatur) und
# ``HashMismatch`` (Inhalt nach dem Signieren verändert) — belegt KEINE
# Signatur über diesen Inhalt.
_SIGNATURE_MATCHING_STATUSES = frozenset({"Valid", "NotTrusted"})

_DLLCHAR_DYNAMIC_BASE = 0x0040   # ASLR
_DLLCHAR_NX_COMPAT = 0x0100      # DEP
_DLLCHAR_GUARD_CF = 0x4000       # Control Flow Guard

_MACHINE_NAMES = {
    0x014C: "x86 (i386)",
    0x8664: "x64 (AMD64)",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}


def _directory_entries(pefile, names: list[str]) -> list[int]:
    """Resolve pefile directory-entry constants (enum in some versions, plain
    dict in others) and drop names that do not exist."""
    out: list[int] = []
    for name in names:
        entry = getattr(pefile.DIRECTORY_ENTRY, name, None)
        if entry is None:
            try:
                entry = pefile.DIRECTORY_ENTRY[name]
            except (KeyError, TypeError):
                entry = None
        if isinstance(entry, int):
            out.append(entry)
    return out


def _count_tls_callbacks(pe, tls_struct) -> int | None:
    """Count the entries of the TLS callback array.

    Returns the number of callbacks, or ``None`` when the array cannot be
    resolved at all. The distinction matters: ``0`` is a statement about the
    file, ``None`` means "unknown" — and an unreadable structure must never
    be dressed up as manipulation.

    pefile exposes ``TlsData.struct`` but never populates ``.callbacks``
    (verified in its ``parse_directory_tls`` source, which returns
    ``TlsData(struct=tls_struct)`` only), so the array is read here.
    ``AddressOfCallBacks`` is a VA pointing at a NULL-terminated list of
    function pointers.

    The walk is capped: a crafted (non-terminated) array must not run away.
    """
    try:
        va = int(getattr(tls_struct, "AddressOfCallBacks", 0) or 0)
    except (TypeError, ValueError):
        return None
    if va == 0:
        # The directory carries no callback pointer at all — a genuine
        # statement by the linker, not a parse failure.
        return 0

    ptr_size = 8 if pe.PE_TYPE == 0x20B else 4
    try:
        raw = pe.get_data(va - pe.OPTIONAL_HEADER.ImageBase, ptr_size * 64)
    except Exception:
        return None
    if len(raw) < ptr_size:
        return None

    count = 0
    for i in range(0, len(raw) - ptr_size + 1, ptr_size):
        if int.from_bytes(raw[i : i + ptr_size], "little") == 0:
            break  # NULL terminator
        count += 1
    return count


def signature_matches_file(status: str | None) -> bool:
    """True when ``status`` belegt eine Signatur, die zum Dateiinhalt passt."""
    return status in _SIGNATURE_MATCHING_STATUSES


def _looks_like_authenticode_blob(overlay: bytes) -> bool:
    """True when the overlay is shaped like an appended WIN_CERTIFICATE.

    Measured on real signed binaries: the overlay starts with the certificate
    length, a revision/type pair and then the DER-encoded PKCS#7 structure
    whose OID (1.2.840.113549.1.1.1 = 06 09 2A 86 48 86 F7 0D) is unmistakable.
    Recognising it by structure keeps a genuinely appended payload flagged,
    while the common case (signed vendor software) stops looking suspicious.

    Layout: dwLength (4) | wRevision (2) | wCertificateType (2) | bCertificate

    The length is checked in BOTH directions: an undersized value would let a
    sample hide a large payload behind a fake signature header.

    Structure is NOT proof: ``dwLength`` comes from the attachment itself, so
    an attacker sets it to the length of their payload and the header agrees
    with itself (measured: 22 freely chosen bytes turned PE_OVERLAY, weight 15,
    into PE_OVERLAY_SIGNATURE, weight 0 — GELB 20 to GRÜN 5). Every caller
    therefore combines this with :func:`signature_matches_file`, the answer of
    the local verification (:func:`authenticode_status`); the combination is
    documented at each call site because the two callers weigh an unverified
    attachment differently.
    """
    if len(overlay) < 16:
        return False
    declared = int.from_bytes(overlay[:4], "little")
    revision = int.from_bytes(overlay[4:6], "little")
    cert_type = int.from_bytes(overlay[6:8], "little")
    # 0x0200 = WIN_CERT_REVISION_2_0, 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA
    if revision != 0x0200 or cert_type != 0x0002:
        return False
    # A real signature covers the overlay essentially completely (up to 8
    # padding bytes); a tiny declared length followed by a large payload is a
    # forged header, not a signature.
    if declared < len(overlay) - 8 - 64 or declared > len(overlay) + 8:
        return False
    head = overlay[:64]
    return _PKCS7_OID in head


def _trailing_certificate_blob(data: bytes) -> bytes | None:
    """Der am Dateiende stehende WIN_CERTIFICATE-Blob, oder ``None``.

    Reiner *Ortungsschritt* für Aufrufer, die den Anhang nicht schon aus dem
    Sektionslayout kennen (die Entropie-Erklärung in ``generic_pipeline``):
    die Zertifikatstabelle steht laut Format hinter dem letzten Sektor, also
    wird vom Dateiende rückwärts nach dem Kopf gesucht (``wRevision`` 0x0200
    und ``wCertificateType`` 0x0002, little endian). Ob der Fund wirklich eine
    Signatur ist, entscheidet ausschließlich :func:`_looks_like_authenticode_blob`.
    """
    marker = b"\x00\x02\x02\x00"
    pos = len(data)
    # Begrenzt: eine präparierte Datei darf keine lange Suche auslösen.
    for _ in range(8):
        pos = data.rfind(marker, 4, pos)
        if pos < 4:
            return None
        candidate = data[pos - 4 :]
        declared = int.from_bytes(candidate[:4], "little")
        if len(candidate) - 8 - 64 <= declared <= len(candidate) + 8:
            return candidate
    return None


def authenticode_explains_entropy(data: bytes, status: str | None) -> bool:
    """True when eine Signatur die hohe Entropie dieser Datei erklärt.

    Ein *verifizierter* Signaturanhang erklärt sie (der Verifizierer hat den
    Inhalt bestätigt, ein Angreifer kann diesen Status nicht schreiben). Ist die
    Datei nachweislich unsigniert oder nach dem Signieren verändert, erklärt
    nichts die Entropie. Ohne Verifizierer (``None``: kein PowerShell, oder ein
    Archiv-Mitglied, für das die Signaturstufe nicht läuft) bleibt es beim
    strukturellen Urteil über den am Dateiende stehenden Blob — nie bei einem
    freien Bytefund: 10 angehängte OID-Bytes hoben ein gepacktes PE von ROT 50
    auf GELB 30. Diese Richtung ist bewusst die vorsichtige: ein signierter,
    selbstentpackender Installer in einem Archiv würde sonst als gepackt gelten,
    und genau dafür existiert die Erklärung.
    """
    if signature_matches_file(status):
        return True
    if status is not None:
        return False
    blob = _trailing_certificate_blob(data)
    return blob is not None and _looks_like_authenticode_blob(blob)


#: Get-AuthenticodeSignature wrapper. The file path travels in an environment
#: variable read by this fixed script — never string-interpolated into a command
#: line, so a hostile filename cannot inject PowerShell syntax.
_AUTHENTICODE_SCRIPT = (
    "$sig = Get-AuthenticodeSignature -FilePath $env:MALAZ_AUTH_PATH; "
    "[pscustomobject]@{Status=[string]$sig.Status; "
    "Message=[string]$sig.StatusMessage; "
    "Subject=[string]$sig.SignerCertificate.Subject; "
    "Issuer=[string]$sig.SignerCertificate.Issuer; "
    "NotBefore=[string]$sig.SignerCertificate.NotBefore; "
    "NotAfter=[string]$sig.SignerCertificate.NotAfter; "
    "Thumbprint=[string]$sig.SignerCertificate.Thumbprint} | ConvertTo-Json"
)


@lru_cache(maxsize=128)
def _probe_signature(
    pwsh: str, target: str, content_sha256: str
) -> tuple[str, str, str, str, str, str, str] | None:
    # ``content_sha256`` wird im Rumpf NICHT gelesen — es ist der
    # CACHE-SCHLUESSEL. vulture meldet es deshalb als "unused variable"
    # (100 % Konfidenz); das ist ein Fehlalarm, und der Parameter MUSS
    # bleiben: ohne ihn cached ``lru_cache`` nach ``(pwsh, target)``, und
    # derselbe Pfad mit inhaltlich anderer Datei bekaeme das alte Urteil
    # zurueck — genau der Fehler, den der Cache-Schluessel behebt.
    """``(Status, Message, Subject)`` von Get-AuthenticodeSignature, offline.

    Der Cache-Schlüssel enthält den **Inhalt** der Datei: ein
    Verifikationsergebnis belegt genau die Bytes, die verifiziert wurden, und
    nichts sonst. Vorher standen dort Pfad, Größe und ``mtime_ns`` — Metadaten
    des Pfades, kein Inhalt: gemessen lieferte ein zweiter Scan desselben
    Pfades mit gleich großer und gleich gealterter, aber inhaltlich anderer
    Datei den Status der VORIGEN Bytes (identische Bytes ergaben je nach
    Cache-Zustand ROT 65 gegen GELB 35; unterdrückt wurden GEN_ENTROPY 30 -> 5
    und PE_UNSIGNED 5 -> PE_SIGNED 0). Eine berührte, unveränderte Datei darf
    ihren Status dagegen behalten — deshalb bleiben Größe und ``mtime_ns``
    ganz draußen (sie würden nur unnötige Neuprüfungen erzeugen).

    Der Cache ist kein Luxus: ZWEI Stufen stellen dieselbe Frage
    (Overlay-Klassifikation und Entropie-Erklärung), und ein zweiter
    PowerShell-Aufruf je Datei würde jeden PE-Scan verdoppeln.
    ``None`` heißt "nicht prüfbar" (kein PowerShell, Timeout, kaputte Ausgabe).
    """
    try:
        env = dict(os.environ)
        env["MALAZ_AUTH_PATH"] = target
        proc = run_tool(
            [pwsh, "-NoProfile", "-NonInteractive", "-Command", _AUTHENTICODE_SCRIPT],
            timeout=20,
            env=env,
        )
        if tool_output_truncated(proc):
            # SEC-023: a cut-off JSON document must never be completed by
            # guesswork — the signature status stays UNKNOWN (None), which
            # every caller reports as "ungeprüft", never as unsigned/valid.
            return None
        _rc, raw_out, _raw_err = proc
        raw = decode_tool_output(raw_out).strip()
        if not raw:
            return None
        data = json.loads(raw)
        if isinstance(data, list):
            data = data[0] if data else {}
        return (
            str(data.get("Status") or ""),
            str(data.get("Message") or ""),
            str(data.get("Subject") or ""),
            str(data.get("Issuer") or ""),
            str(data.get("NotBefore") or ""),
            str(data.get("NotAfter") or ""),
            str(data.get("Thumbprint") or ""),
        )
    except Exception:
        return None


def _content_sha256(ctx: AnalysisContext) -> str:
    """SHA-256 der Bytes, auf die ein Verifikationsergebnis sich beziehen darf.

    ``ctx.sha256`` ist der vom Dispatcher gestreamte Hash der KOMPLETTEN Datei
    — genau die Datei, die der Verifizierer liest; er bleibt deshalb auch für
    Dateien oberhalb der Lesekappung gültig. Fehlt er, taugen nur die
    vorliegenden Bytes als Schlüssel, und auch die nur, wenn sie die ganze
    Datei sind: der Hash eines gekappten Präfix würde zwei verschiedene Dateien
    in denselben Cache-Eintrag legen — genau der Fehler, den dieser Schlüssel
    verhindern soll. Ohne Inhaltsbindung gibt es deshalb keinen Schlüssel.
    """
    if ctx.sha256:
        return ctx.sha256
    if ctx.size == len(ctx.data):
        return hashlib.sha256(ctx.data).hexdigest()
    return ""


def _signature_facts(
    ctx: AnalysisContext,
) -> tuple[str, str, str, str, str, str, str] | None:
    """Verifikationsergebnis für die analysierte Datei, ``None`` wenn unbekannt."""
    if os.name != "nt" or ctx.depth != 0:
        return None
    content = _content_sha256(ctx)
    if not content:
        # Ohne Inhaltsbindung ist kein Urteil über DIESE Bytes zu haben (ein
        # gekappter Puffer ohne Dateihash): dann "ungeprüft" statt einer
        # Aussage, die zu anderen Bytes gehören kann.
        return None
    try:
        target = Path(ctx.path)
        if not target.is_file():
            return None
        pwsh = which_absolute("powershell") or which_absolute("pwsh")
    except Exception:
        return None
    if not pwsh:
        return None
    return _probe_signature(pwsh, str(target), content)


def authenticode_status(ctx: AnalysisContext) -> str | None:
    """Der verifizierte Signaturstatus der Datei, oder ``None`` (ungeprüft).

    Gemeinsamer Einstieg für beide Nutzer derselben Aussage: die
    Overlay-Klassifikation (``PE_OVERLAY`` gegen ``PE_OVERLAY_SIGNATURE``) und
    die Entropie-Erklärung in ``generic_pipeline``.
    """
    facts = _signature_facts(ctx)
    return facts[0] if facts else None


def _publisher_name(subject: str) -> str:
    """Extract the CN (or O) from a certificate subject string, best effort."""
    if not subject:
        return ""
    for field_name in ("CN=", "O="):
        idx = subject.find(field_name)
        if idx == -1:
            continue
        rest = subject[idx + len(field_name) :]
        end = len(rest)
        for sep in (",", ";"):
            pos = rest.find(sep)
            if pos != -1:
                end = min(end, pos)
        value = rest[:end].strip()
        if value:
            return value
    return subject.strip()


def match_import_patterns(imported: set[str]) -> list[tuple[str, str, list[str]]]:
    """Return ``(rule_id, label, matched_imports)`` for every pattern that
    fires (each group of the pattern has at least one imported function)."""
    out: list[tuple[str, str, list[str]]] = []
    for rule_id, label, groups in _IMPORT_PATTERNS:
        matched: list[str] = []
        for group in groups:
            hit = next((g for g in group if g in imported), None)
            if hit is None:
                break
            matched.append(hit)
        else:
            out.append((rule_id, label, matched))
    return out


# DIE results are pure content facts (packer/compiler names) and independent
# of the filename. Keyed by content hash + binary mtime, so a DIE update
# invalidates the cache; bounded so a folder scan cannot grow it without end.
_DIE_CACHE: OrderedDict[tuple, tuple[dict, ...]] = OrderedDict()
_DIE_CACHE_LOCK = threading.Lock()
_DIE_CACHE_MAX = 256


class PePipeline(Pipeline):
    name = "pe"

    def analyze(self, ctx: AnalysisContext) -> list[Indicator]:
        if ctx.detected_type != "pe":
            return []
        indicators: list[Indicator] = []
        indicators.extend(self._structure(ctx))
        indicators.extend(self._imports(ctx))
        indicators.extend(self._mitigations(ctx))
        # Signature status FIRST (the trust signal other heuristics depend on),
        # then the three optional external stages. They are independent
        # subprocess waits (Authenticode/PowerShell, DIE, capa); running them
        # concurrently cuts the per-PE wall time from their sum to the slowest.
        # Results are appended in the original order, so the report stays
        # deterministic.
        with ThreadPoolExecutor(max_workers=3) as pool:
            auth_future = pool.submit(self._authenticode, ctx)
            die_future = pool.submit(self._die, ctx)
            capa_future = pool.submit(self._capa, ctx)
            indicators.extend(auth_future.result())
            indicators.extend(die_future.result())
            indicators.extend(capa_future.result())
        return indicators

    # -- stage 1: structure ------------------------------------------------- #

    def _structure(self, ctx: AnalysisContext) -> list[Indicator]:
        try:
            import pefile
        except Exception:
            return [
                self._indicator(
                    "PE_LIB_MISSING",
                    "pefile nicht verfügbar — PE-Tiefenanalyse übersprungen",
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            ]

        out: list[Indicator] = []
        try:
            pe = pefile.PE(data=ctx.data, fast_load=True)
            pe.parse_data_directories(
                directories=_directory_entries(
                    pefile,
                    [
                        "IMAGE_DIRECTORY_ENTRY_IMPORT",
                        "IMAGE_DIRECTORY_ENTRY_DEBUG",
                        "IMAGE_DIRECTORY_ENTRY_TLS",
                        "IMAGE_DIRECTORY_ENTRY_RESOURCE",
                        "IMAGE_DIRECTORY_ENTRY_EXPORT",
                        "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
                        "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
                    ],
                )
            )
        except Exception as exc:
            # "Not analysable" must never look like "clean" (the project's
            # documented contract). A PE whose headers cannot be parsed yields
            # NO section/import/mitigation findings at all, so an INFO with
            # weight 0 would report a score of 0 for a file that was never
            # actually inspected. A deliberately malformed header is also a
            # known anti-analysis technique. LOW/5 keeps it proportionate:
            # visible and non-zero, but far from a false alarm (audit finding).
            return [
                self._indicator(
                    "PE_PARSE_WARN",
                    "PE konnte nicht geparst werden",
                    detail=(
                        f"{type(exc).__name__}: {exc} — Sektionen, Importe und "
                        "Mitigationen wurden nicht geprüft; das Ergebnis ist "
                        "nicht als 'sauber' zu werten."
                    ),
                    severity=Severity.LOW,
                    category=CAT_STRUCTURE,
                    weight=5,
                )
            ]

        try:
            machine = _MACHINE_NAMES.get(
                pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:04x}"
            )
            out.append(
                self._indicator(
                    "PE_HEADER",
                    f"PE-Header: {machine}",
                    detail=(
                        f"Maschine {machine}, {len(pe.sections)} Sektionen, "
                        f"Zeitstempel {pe.FILE_HEADER.TimeDateStamp}"
                    ),
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            )
        except Exception:
            pass

        # -- sections -------------------------------------------------------- #
        try:
            high_entropy: list[str] = []
            unusual: list[str] = []
            zero_raw: list[str] = []
            rwx: list[str] = []
            raw_end = 0
            raw_beyond_eof: list[str] = []
            raw_beyond_eof_count = 0
            entropy_skipped = 0
            entropy_truncated = 0
            entropy_truncated_names: list[str] = []
            for index, section in enumerate(pe.sections):
                name = section.Name.rstrip(b"\x00") or b"(leer)"
                display = name.decode("latin-1", "replace")
                declared_end = section.PointerToRawData + section.SizeOfRawData
                if section.SizeOfRawData and declared_end > len(ctx.data):
                    # A forged SizeOfRawData can declare an appended payload as
                    # section content and hide the overlay (BUG-031). The value
                    # is reported; the overlay boundary itself is clamped so no
                    # slice can read past the file.
                    raw_beyond_eof_count += 1
                    if len(raw_beyond_eof) < 8:
                        raw_beyond_eof.append(
                            f"{display} (SizeOfRawData {section.SizeOfRawData}, "
                            f"Ende {declared_end} > Datei {len(ctx.data)})"
                        )
                raw_end = max(raw_end, min(declared_end, len(ctx.data)))
                try:
                    if index >= _SECTION_ENTROPY_MAX_SECTIONS:
                        entropy_skipped += 1
                        entropy = 0.0
                    else:
                        raw_len = min(
                            section.SizeOfRawData, _SECTION_ENTROPY_MAX_BYTES
                        )
                        if section.SizeOfRawData > _SECTION_ENTROPY_MAX_BYTES:
                            entropy_truncated += 1
                            if len(entropy_truncated_names) < 4:
                                entropy_truncated_names.append(display)
                        entropy = shannon_entropy(section.get_data(length=raw_len))
                except Exception:
                    entropy = 0.0
                if entropy > 7.5:
                    high_entropy.append(f"{name.decode('latin-1', 'replace')} "
                                        f"({entropy:.2f})")
                lname = name.lower()
                if lname in _PACKER_SECTION_NAMES:
                    unusual.append(name.decode("latin-1", "replace"))
                # A section with no raw data but a virtual size is the normal
                # layout for uninitialised memory — compilers and installers
                # (PyInstaller and friends) emit it under many names
                # (.bss, .tls, .ndata, …). Measured: git-bash.exe and
                # "Uninstall ZCode.exe" both scored RED from this alone.
                # Genuinely suspicious is the COMBINATION that no compiler
                # produces: zero raw data AND writable AND executable.
                if (
                    section.SizeOfRawData == 0
                    and section.Misc_VirtualSize > 0
                    and lname.lstrip(b".") not in _NORMAL_ZERO_RAW_SECTIONS
                    and (section.Characteristics & 0x80000000)  # MEM_WRITE
                    and (section.Characteristics & 0x20000000)  # MEM_EXECUTE
                ):
                    zero_raw.append(name.decode("latin-1", "replace"))

                if (section.Characteristics & 0x80000000) and (
                    section.Characteristics & 0x20000000
                ):
                    rwx.append(name.decode("latin-1", "replace"))

            if raw_beyond_eof_count:
                out.append(
                    self._indicator(
                        "PE_SECTION_RAW_OOB",
                        f"SizeOfRawData über Dateiende ({raw_beyond_eof_count})",
                        detail=(
                            "Mindestens eine Sektion deklariert Rohdaten, die "
                            "über das Dateiende hinausreichen: "
                            + "; ".join(raw_beyond_eof[:8])
                            + ". Das Overlay wurde nur bis zum tatsächlichen "
                            "Dateiende ausgewertet; angehängter Inhalt kann so "
                            "als Sektionsrohdaten erscheinen."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_STRUCTURE,
                        weight=15,
                    )
                )

            if entropy_skipped or entropy_truncated:
                parts: list[str] = []
                if entropy_truncated:
                    parts.append(
                        "Entropie je Sektion auf "
                        f"{_SECTION_ENTROPY_MAX_BYTES} Bytes begrenzt "
                        f"({entropy_truncated} Sektion(en)): "
                        + ", ".join(entropy_truncated_names)
                    )
                if entropy_skipped:
                    parts.append(
                        f"Entropie nur für die ersten "
                        f"{_SECTION_ENTROPY_MAX_SECTIONS} von "
                        f"{len(pe.sections)} Sektionen berechnet "
                        f"({entropy_skipped} übersprungen)"
                    )
                out.append(
                    self._indicator(
                        "PE_SECTION_ENTROPY_LIMIT",
                        "Sektionsanalyse durch Arbeitsbudget begrenzt",
                        detail=(
                            "Die Sektionsentropie ist ein Arbeitsbudget, kein "
                            "Vollständigkeitsversprechen: "
                            + "; ".join(parts)
                            + ". Nicht berechnete Sektionen können Packer-"
                            "Hinweise verbergen."
                        ),
                        severity=Severity.INFO,
                        category=CAT_STRUCTURE,
                        weight=0,
                    )
                )

            if unusual or zero_raw:
                out.append(
                    self._indicator(
                        "PE_PACKED",
                        "Packer-typische Sektionen: " + ", ".join(unusual + zero_raw),
                        detail=(
                            "Sektionsnamen oder Layout deuten auf einen Packer "
                            "(z. B. UPX, MPRESS, VMProtect)."
                        ),
                        severity=Severity.HIGH,
                        category=CAT_FORMAT,
                        weight=30,
                    )
                )
            elif len(high_entropy) >= 2:
                out.append(
                    self._indicator(
                        "PE_HIGH_ENTROPY_SECTIONS",
                        f"Mehrere Sektionen mit hoher Entropie ({len(high_entropy)})",
                        detail="Sektionen: " + ", ".join(high_entropy[:8]),
                        severity=Severity.MEDIUM,
                        category=CAT_FORMAT,
                        weight=15,
                    )
                )

            if rwx:
                out.append(
                    self._indicator(
                        "PE_RWX_SECTION",
                        "Schreibbare und ausführbare Sektion(en)",
                        detail=(
                            "Sektionen mit WRITE+EXECUTE: "
                            + ", ".join(rwx[:8])
                            + ". Manche JIT-Engines tun das legitim; "
                            "gleichzeitig ist es die klassische Form "
                            "selbstmodifizierenden Codes."
                        ),
                        severity=Severity.INFO,
                        category=CAT_STRUCTURE,
                        weight=0,
                    )
                )

            # Overlay: data after the last raw section end.
            if raw_end > 0 and raw_end < len(ctx.data):
                overlay = ctx.data[raw_end:]
                ent = shannon_entropy(overlay)
                # An appended Authenticode signature is a WIN32 certificate
                # blob, not a hidden payload. Measured on 240 legitimate
                # programs: 65% carry such an overlay with high entropy, and
                # reporting them made PE_OVERLAY fire on 70% of all normal
                # software (including Microsoft's own binaries).
                #
                # The blob counts as a signature only when the LOCAL
                # VERIFICATION confirms it (Get-AuthenticodeSignature, see
                # authenticode_status): the shape alone is attacker-chosen
                # (measured: 22 freely chosen header bytes turned PE_OVERLAY,
                # weight 15, into PE_OVERLAY_SIGNATURE, weight 0 — GELB 20 to
                # GRÜN 5). Is the attachment not confirmed — unsigned, modified
                # after signing, or unverifiable — it stays content and is
                # scored as such.
                status = authenticode_status(ctx)
                signature_shaped = _looks_like_authenticode_blob(overlay)
                if signature_shaped and signature_matches_file(status):
                    out.append(
                        self._indicator(
                            "PE_OVERLAY_SIGNATURE",
                            f"Signatur-Anhang ({len(overlay)} Bytes)",
                            detail=(
                                "Nach dem letzten Sektor folgt die "
                                "Authenticode-Signatur — das ist bei "
                                "signierter Software normal und kein "
                                "versteckter Inhalt."
                            ),
                            severity=Severity.INFO,
                            category=CAT_STRUCTURE,
                            weight=0,
                        )
                    )
                else:
                    if signature_shaped:
                        reason = (
                            "der Signatur-Kopf wurde nicht bestätigt "
                            f"(Verifikation: {status or 'nicht verfügbar'})"
                        )
                    else:
                        reason = "kein Signatur-Anhang"
                    out.append(
                        self._indicator(
                            "PE_OVERLAY",
                            f"Overlay-Daten ({len(overlay)} Bytes)",
                            detail=(
                                f"Nach dem letzten Sektoren-Ende folgen {len(overlay)} "
                                f"Bytes (Entropie {ent:.2f}) — {reason}, daher "
                                "möglicher angehängter Inhalt."
                            ),
                            severity=Severity.MEDIUM if ent > 7.5 else Severity.LOW,
                            category=CAT_RESOURCE,
                            weight=15 if ent > 7.5 else 5,
                        )
                    )
        except Exception as exc:
            out.append(
                self._indicator(
                    "PE_SECTION_PARSE_WARN",
                    "Sektions-Analyse fehlerhaft",
                    detail=(
                        f"{type(exc).__name__}: {exc} — Packer-/Overlay-Befunde "
                        "sind unvollständig."
                    ),
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            )

        # -- strings (AP9 foundation) --------------------------------------- #
        # Section-aware, bounded ASCII/UTF-16LE extraction. Rules stay at
        # weight 0 until a fixture + benign counterexample calibrates them;
        # the anti-duplication contract with BINARY_IOC lives in
        # _PE_SUSPICIOUS_STRINGS (no addresses).
        out.extend(self._strings(ctx, pe))

        # -- TLS callbacks --------------------------------------------------- #
        try:
            tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
            tls_struct = getattr(tls, "struct", None) if tls is not None else None
            if tls_struct is not None:
                # pefile fills TlsData.struct but NOT .callbacks (verified in
                # its parse_directory_tls source), so the earlier
                # `getattr(tls, "callbacks")` was always empty — the finding
                # read "TLS-Callbacks vorhanden (0)" and the PE_TLS_EMPTY
                # branch could never fire. The callback count has to come from
                # the structure itself: AddressOfCallBacks points to a
                # NULL-terminated array of VAs.
                count = _count_tls_callbacks(pe, tls_struct)
                if count is None:
                    # Not resolvable from the file — say nothing rather than
                    # dressing an unreadable structure up as manipulation.
                    pass
                elif count == 0:
                    # MEASURED: 60 of 202 real binaries (30%) genuinely carry an
                    # empty callback array — the array IS readable and its
                    # first entry is NULL (verified against the raw bytes).
                    # A TLS directory without callbacks is a legitimate
                    # compiler artefact, so this stays a note without weight.
                    out.append(
                        self._indicator(
                            "PE_TLS_EMPTY",
                            "TLS-Directory ohne Callbacks",
                            detail=(
                                "Das TLS-Verzeichnis ist vorhanden, enthält "
                                "aber keine Callback-Adressen. Bei 30% der "
                                "untersuchten Programme der Fall und daher "
                                "kein Hinweis für sich."
                            ),
                            severity=Severity.INFO,
                            category=CAT_STRUCTURE,
                            weight=0,
                        )
                    )
                else:
                    # MEASURED: 75% of 240 legitimate programs carry TLS
                    # callbacks — C/C++ runtimes use them for thread-local
                    # initialisation, so mere presence is not a signal.
                    out.append(
                        self._indicator(
                            "PE_TLS_CALLBACKS",
                            f"TLS-Callbacks vorhanden ({count})",
                            detail=(
                                "TLS-Callbacks laufen VOR dem Entry-Point. Das "
                                "ist bei C/C++-Programmen normal (Thread-Local-"
                                "Initialisierung); Packer nutzen es ebenfalls. "
                                "Ohne weitere Auffälligkeiten kein starker "
                                "Hinweis."
                            ),
                            severity=Severity.LOW,
                            category=CAT_STRUCTURE,
                            weight=3,
                        )
                    )
        except Exception as exc:
            out.append(
                self._indicator(
                    "PE_TLS_PARSE_WARN",
                    "TLS-Analyse fehlerhaft",
                    detail=f"{type(exc).__name__}: {exc} — TLS-Befunde unvollständig.",
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            )

        # -- PDB / debug path ------------------------------------------------ #
        try:
            pdb_paths, pdb_dropped, pdb_clipped = _pdb_paths(pe)
            if pdb_paths:
                detail = " | ".join(pdb_paths[:5])
                if pdb_dropped or pdb_clipped:
                    detail += (
                        f" | gekürzt: {pdb_dropped} weitere Debug-Einträge "
                        f"nicht gelesen, {pdb_clipped} Namen auf "
                        f"{_PDB_NAME_MAX} Zeichen begrenzt"
                    )
                out.append(
                    self._indicator(
                        "PE_PDB",
                        "PDB-Pfad vorhanden: " + pdb_paths[0],
                        detail=detail,
                        severity=Severity.INFO,
                        category=CAT_STRUCTURE,
                        weight=0,
                    )
                )
        except Exception:
            pass

        # -- resources / manifest / version / Rich / .NET / exports ---------- #
        # All AP10 metadata is weight 0: it is report evidence, not a
        # calibrated malware signal. Parsing is bounded and degrades silently
        # to "no finding" only for genuinely absent structures.
        out.extend(self._resources(ctx, pe))
        out.extend(self._rich_header_facts(ctx, pe))
        out.extend(self._dotnet_facts(pe))
        out.extend(self._exports(pe))

        with suppress(Exception):
            pe.close()
        return out

    def _resources(self, ctx: AnalysisContext, pe) -> list[Indicator]:
        """Resource inventory, embedded manifest and selected version fields."""
        out: list[Indicator] = []
        root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        entries = list(getattr(root, "entries", []) or []) if root else []
        if entries:
            types = []
            for entry in entries[:12]:
                names = getattr(getattr(entry, "directory", None), "entries", []) or []
                labels = []
                for name_entry in names[:3]:
                    label = _resource_entry_name(name_entry)[:_RESOURCE_NAME_MAX]
                    langs = [
                        str(getattr(lang_entry, "id", "?"))
                        for lang_entry in getattr(
                            getattr(name_entry, "directory", None), "entries", []
                        )
                        or []
                    ]
                    if langs:
                        label += "[" + ",".join(langs[:3]) + "]"
                    labels.append(label)
                more_names = f" +{len(names) - 3}" if len(names) > 3 else ""
                type_name = _resource_entry_name(entry)[:_RESOURCE_NAME_MAX]
                detail_names = (
                    ": " + ", ".join(labels) + more_names if labels else ""
                )
                types.append(f"{type_name} ({len(names)}){detail_names}")
            more = f" (+{len(entries) - 12} weitere)" if len(entries) > 12 else ""
            detail = "Typen: " + ", ".join(types) + more
            if len(detail) > _RESOURCE_DETAIL_MAX:
                detail = detail[:_RESOURCE_DETAIL_MAX] + " …"
            out.append(
                self._indicator(
                    "PE_RESOURCES",
                    f"Ressourcen: {len(entries)} Typen",
                    detail=detail,
                    severity=Severity.INFO,
                    category=CAT_RESOURCE,
                    weight=0,
                )
            )

        manifest = _resource_data(pe, 24, None)  # RT_MANIFEST, any name ID
        if manifest is not None:
            facts = _manifest_facts(manifest)
            detail = (
                " | ".join(f"{key}={value}" for key, value in facts.items())
                if facts
                else "Manifest vorhanden, aber ohne requestedExecutionLevel/"
                "uiAccess/autoElevate."
            )
            out.append(
                self._indicator(
                    "PE_MANIFEST",
                    "Eingebettetes Anwendungsmanifest",
                    detail=detail,
                    severity=Severity.INFO,
                    category=CAT_RESOURCE,
                    weight=0,
                )
            )

        version = _version_strings(pe)
        if version:
            out.append(
                self._indicator(
                    "PE_VERSION_INFO",
                    "Versionsinformationen vorhanden",
                    detail=" | ".join(f"{key}={value}" for key, value in version.items()),
                    severity=Severity.INFO,
                    category=CAT_RESOURCE,
                    weight=0,
                )
            )
        return out

    def _rich_header_facts(self, ctx: AnalysisContext, pe) -> list[Indicator]:
        pe_offset = int(getattr(getattr(pe, "DOS_HEADER", None), "e_lfanew", 0) or 0)
        decoded = _rich_header(ctx.data, pe_offset)
        if decoded is None:
            return []
        key, entries = decoded
        builds = ", ".join(f"0x{compid:08x}×{count}" for compid, count in entries[:8])
        more = f" (+{len(entries) - 8} weitere)" if len(entries) > 8 else ""
        return [
            self._indicator(
                "PE_RICH_HEADER",
                f"Rich-Header: {len(entries)} Build-Einträge",
                detail=f"XOR-Key 0x{key:08x}; Einträge: {builds}{more}",
                severity=Severity.INFO,
                category=CAT_STRUCTURE,
                weight=0,
            )
        ]

    def _dotnet_facts(self, pe) -> list[Indicator]:
        directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", None) or []
        if len(directories) <= 14:
            return []
        com = directories[14]  # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
        if not getattr(com, "VirtualAddress", 0):
            return []
        version = ""
        try:
            raw = pe.get_data(com.VirtualAddress, min(int(com.Size), 16))
        except Exception:
            raw = b""
        if len(raw) >= 8:
            major = int.from_bytes(raw[4:6], "little")
            minor = int.from_bytes(raw[6:8], "little")
            version = f"{major}.{minor}"
        else:
            descriptor = getattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR", None)
            struct_value = getattr(descriptor, "struct", None)
            if struct_value is not None:
                version = (
                    f"{getattr(struct_value, 'MajorRuntimeVersion', '?')}."
                    f"{getattr(struct_value, 'MinorRuntimeVersion', '?')}"
                )
        detail = f"CLR-Header an RVA 0x{com.VirtualAddress:x}, {com.Size} Bytes"
        if version:
            detail += f", Runtime-Version {version}"
        return [
            self._indicator(
                "PE_DOTNET",
                "Verwaltetes .NET-Programm",
                detail=detail,
                severity=Severity.INFO,
                category=CAT_STRUCTURE,
                weight=0,
            )
        ]

    def _exports(self, pe) -> list[Indicator]:
        export = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        symbols = list(getattr(export, "symbols", []) or []) if export else []
        if not symbols:
            return []
        names = []
        forwarders = sum(
            1 for symbol in symbols if getattr(symbol, "forwarder", None)
        )
        for symbol in symbols[:8]:
            name = getattr(symbol, "name", None)
            label = (
                name.decode("latin-1", "replace")
                if isinstance(name, bytes) and name
                else f"#{getattr(symbol, 'ordinal', '?')}"
            )
            names.append(label)
        more = f" (+{len(symbols) - 8} weitere)" if len(symbols) > 8 else ""
        detail = f"{len(symbols)} Exporte: " + ", ".join(names) + more
        if forwarders:
            detail += f"; davon {forwarders} Weiterleitungen"
        return [
            self._indicator(
                "PE_EXPORTS",
                f"Exporte: {len(symbols)}",
                detail=detail,
                severity=Severity.INFO,
                category=CAT_STRUCTURE,
                weight=0,
            )
        ]

    def _strings(self, ctx: AnalysisContext, pe) -> list[Indicator]:
        """Bounded string extraction with section attribution (weight 0)."""
        try:
            sections = tuple(
                SectionSpan(
                    name=(section.Name.rstrip(b"\x00") or b"(leer)").decode(
                        "latin-1", "replace"
                    ),
                    offset=int(section.PointerToRawData),
                    size=int(section.SizeOfRawData),
                )
                for section in pe.sections
                if section.SizeOfRawData
            )
        except Exception:
            sections = ()
        result = extract_strings(ctx.data, sections=sections)
        out: list[Indicator] = []

        if result.capped:
            cap_names = {
                "bytes": "Byte-Limit",
                "count": "Anzahl-Limit",
                "length": "Längen-Limit",
            }
            detail = (
                f"{len(result.strings)} Strings aus "
                f"{result.scanned_bytes} Bytes; Limit: "
                + ", ".join(cap_names.get(cap, cap) for cap in result.caps)
                + "."
            )
            if {"bytes", "count"} & set(result.caps):
                detail += (
                    " Der Rest der Datei wurde NICHT nach Strings durchsucht."
                )
            else:
                # Only values longer than the per-string limit were cut; the
                # whole buffer was still scanned. The old sentence claimed a
                # partial scan and was false for this case.
                detail += (
                    " Die Datei wurde vollständig durchsucht; einzelne "
                    "Strings wurden auf die Maximallänge gekürzt."
                )
            out.append(
                self._indicator(
                    "PE_STRINGS_SUMMARY",
                    "String-Extraktion gekappt",
                    detail=detail,
                    severity=Severity.INFO,
                    category=CAT_CONTENT,
                    weight=0,
                )
            )

        tokens, examples = _suspicious_string_hits(result)
        if tokens:
            out.append(
                self._indicator(
                    "PE_STRINGS_SUSPICIOUS",
                    "Verdächtige Befehls-Strings im Programm",
                    detail=(
                        "Gefunden: "
                        + ", ".join(tokens[:_PE_SUSPICIOUS_DETAIL_LIMIT])
                        + (
                            f" (+{len(tokens) - _PE_SUSPICIOUS_DETAIL_LIMIT} weitere)"
                            if len(tokens) > _PE_SUSPICIOUS_DETAIL_LIMIT
                            else ""
                        )
                        + ". Beispiele: "
                        + " · ".join(examples)
                        + ". Die Strings wurden nur gelesen, nie ausgeführt."
                    ),
                    # Gewicht 0: die Extraktion ist die Grundlage, die
                    # Bewertung braucht erst Fixture + harmlose Gegenprobe.
                    severity=Severity.INFO,
                    category=CAT_CONTENT,
                    weight=0,
                )
            )
        return out

    # -- stage 2: imports ---------------------------------------------------- #

    def _imports(self, ctx: AnalysisContext) -> list[Indicator]:
        try:
            import pefile
        except Exception:
            return []

        out: list[Indicator] = []
        pe = None
        try:
            pe = pefile.PE(data=ctx.data, fast_load=True)
            pe.parse_data_directories(
                directories=_directory_entries(
                    pefile,
                    [
                        "IMAGE_DIRECTORY_ENTRY_IMPORT",
                        "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
                    ],
                )
            )
        except Exception as exc:
            with suppress(Exception):
                if pe is not None:
                    pe.close()
            return [
                self._indicator(
                    "PE_IMPORT_PARSE_WARN",
                    "Import-Analyse fehlerhaft",
                    detail=(
                        f"{type(exc).__name__}: {exc} — Import-Muster wurden "
                        "nicht geprüft."
                    ),
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            ]

        try:
            imported: set[str] = set()
            dlls: list[str] = []
            # getattr, not attribute access: pefile only sets
            # DIRECTORY_ENTRY_IMPORT when the import directory exists, and a
            # plain pe.DIRECTORY_ENTRY_IMPORT raised AttributeError for a PE
            # without one. The enclosing `except Exception` swallowed it, so
            # the WHOLE import stage silently produced nothing — which made
            # PE_NO_IMPORTS (the rule meant to flag packed binaries) dead code.
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or []:
                dll = (entry.dll or b"").decode("latin-1", "replace")
                if dll:
                    dlls.append(dll)
                for imp in entry.imports or []:
                    name = imp.name
                    if name:
                        imported.add(name.decode("latin-1", "replace").lower())

            # Delay imports are still imports: they feed the SAME pattern
            # matcher (one finding per pattern, never a second PE_IMPORT_*
            # row) and get one informational summary of their own.
            delay_dlls: list[str] = []
            delay_count = 0
            for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", None) or []:
                dll = (getattr(entry, "dll", b"") or b"").decode(
                    "latin-1", "replace"
                )
                if dll:
                    dlls.append(dll)
                    delay_dlls.append(dll)
                for imp in getattr(entry, "imports", None) or []:
                    name = getattr(imp, "name", None)
                    if name:
                        imported.add(name.decode("latin-1", "replace").lower())
                        delay_count += 1

            if delay_dlls:
                out.append(
                    self._indicator(
                        "PE_DELAY_IMPORTS",
                        f"Delay-Importe: {len(delay_dlls)} DLL(s)",
                        detail=(
                            f"{delay_count} Funktion(en) aus "
                            + ", ".join(delay_dlls[:8])
                            + " werden erst zur Laufzeit geladen."
                        ),
                        severity=Severity.INFO,
                        category=CAT_STRUCTURE,
                        weight=0,
                    )
                )

            if not dlls:
                out.append(
                    self._indicator(
                        "PE_NO_IMPORTS",
                        "Keine Importe sichtbar",
                        detail="Typisch für gepackte/verschleierte Binaries.",
                        severity=Severity.MEDIUM,
                        category=CAT_STRUCTURE,
                        weight=15,
                    )
                )

            # imphash fingerprint (report value, no score).
            try:
                imphash = pe.get_imphash()
                if imphash:
                    out.append(
                        self._indicator(
                            "PE_IMPHASH",
                            f"imphash: {imphash}",
                            detail="Import-Fingerabdruck für Korrelation.",
                            severity=Severity.INFO,
                            category=CAT_SIGNATURE,
                            weight=0,
                        )
                    )
            except Exception:
                pass

            # Suspicious combinations. Weights are calibrated per pattern
            # because they differ sharply in how much they actually prove:
            #   * KEYLOG: SetWindowsHookEx/GetAsyncKeyState are used by any
            #     software with global hotkeys or macro support (measured:
            #     unins000.exe, shell32.dll) — weak.
            #   * INJECTION: even the full triad appears in software that
            #     isolates plugins (measured: firefox.exe) — weak.
            #   * DOWNLOAD_EXEC: an actual download call combined with an
            #     execution call is the most specific of the three, but still
            #     only an indicator.
            # None of them is an anchor; YARA/AV/behaviour carry the verdict.
            for rule_id, label, matched in match_import_patterns(imported):
                sev, weight = _IMPORT_WEIGHTS.get(
                    rule_id, (Severity.LOW, 5)
                )
                out.append(
                    self._indicator(
                        rule_id,
                        f"{label}: " + ", ".join(matched),
                        detail=(
                            "API-Kombination im Import-Tab. Sie allein belegt "
                            "keine Schadsoftware — dieselben APIs nutzen auch "
                            "legitime Programme (Plugin-Isolation, globale "
                            "Tastenkürzel, Updater)."
                        ),
                        severity=sev,
                        category=CAT_SIGNATURE,
                        weight=weight,
                    )
                )
        except Exception:
            pass

        with suppress(Exception):
            pe.close()
        return out

    # -- stage 3: mitigations ------------------------------------------------ #

    def _mitigations(self, ctx: AnalysisContext) -> list[Indicator]:
        try:
            import pefile
        except Exception:
            return []
        pe = None
        try:
            pe = pefile.PE(data=ctx.data, fast_load=True)
            chars = pe.OPTIONAL_HEADER.DllCharacteristics
        except Exception:
            # A missing/garbled optional header simply yields no mitigation
            # info; still close the parsed object on the way out.
            with suppress(Exception):
                if pe is not None:
                    pe.close()
            return []
        with suppress(Exception):
            pe.close()

        # MEASURED on 240 legitimate programs: CFG is missing in 28% of them
        # (older software, MinGW/GCC builds) while ASLR/DEP are missing in ~1%.
        # CFG absence is a hardening gap, not a malware signal — it made
        # PE_WEAK_MITIGATIONS fire on 40% of normal software and drove 16 of
        # the remaining YELLOW verdicts. Only ASLR/DEP (the two the industry
        # has treated as mandatory for a decade) remain scored; CFG is
        # reported as an informational note.
        missing = []
        notes = []
        if not (chars & _DLLCHAR_DYNAMIC_BASE):
            missing.append("ASLR")
        if not (chars & _DLLCHAR_NX_COMPAT):
            missing.append("DEP/NX")
        if not (chars & _DLLCHAR_GUARD_CF):
            notes.append("Control Flow Guard")
        out: list[Indicator] = []
        if missing:
            out.append(
                self._indicator(
                    "PE_WEAK_MITIGATIONS",
                    "Fehlende Exploit-Mitigationen: " + ", ".join(missing),
                    detail=(
                        "Die Binary ist ohne "
                        + "/".join(missing)
                        + " gebaut — ältere oder bewusst schlecht gehärtete "
                        "Software."
                    ),
                    severity=Severity.LOW,
                    category=CAT_STRUCTURE,
                    weight=5,
                )
            )
        if notes:
            out.append(
                self._indicator(
                    "PE_MITIGATION_NOTE",
                    "Ohne Control Flow Guard gebaut",
                    detail=(
                        "CFG fehlt. Das ist bei älterer Software und bei "
                        "MinGW/GCC-Builds verbreitet (in einer Stichprobe bei "
                        "28 % der Programme) und daher kein Schadhinweis."
                    ),
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            )
        return out

    # -- stage 4: authenticode ---------------------------------------------- #

    def _authenticode(self, ctx: AnalysisContext) -> list[Indicator]:
        """Signature validity via local PowerShell (Windows only, offline).

        The status comes from the shared probe (:func:`_signature_facts`): the
        overlay classification and the entropy explanation ask the same
        question, and ``_probe_signature`` answers it once per file.
        """
        facts = _signature_facts(ctx)
        if facts is None:
            return []
        status, message, subject, issuer, not_before, not_after, thumbprint = facts

        mapping = {
            "Valid": ("PE_SIGNED", "Digital signiert (gültig)", Severity.INFO, 0),
            "NotSigned": (
                "PE_UNSIGNED",
                "Nicht digital signiert",
                Severity.LOW,
                5,
            ),
            "HashMismatch": (
                "PE_SIGNATURE_INVALID",
                "Signatur passt NICHT zum Dateiinhalt",
                Severity.HIGH,
                30,
            ),
            "Invalid": (
                "PE_SIGNATURE_INVALID",
                "Signatur ungültig",
                Severity.HIGH,
                30,
            ),
            "NotTrusted": (
                "PE_SIGNATURE_UNTRUSTED",
                "Signatur nicht vertrauenswürdig",
                Severity.MEDIUM,
                15,
            ),
        }
        entry = mapping.get(status)
        if entry is None:
            return []
        rule_id, title, severity, weight = entry
        detail = message or f"Status: {status}"
        publisher = _publisher_name(subject)
        if publisher:
            detail += f" | Herausgeber: {publisher}"
        meta = []
        if issuer:
            meta.append(f"Aussteller: {issuer[:200]}")
        if not_before or not_after:
            meta.append(f"Gültig: {not_before[:80] or '?'} bis {not_after[:80] or '?'}")
        if thumbprint:
            meta.append(f"Fingerabdruck: {thumbprint[:80]}")
        if meta:
            detail += " | " + " | ".join(meta)
        return [
            self._indicator(
                rule_id,
                title,
                detail=detail,
                severity=severity,
                category=CAT_STRUCTURE,
                weight=weight,
            )
        ]

    # -- stage 5: Detect It Easy -------------------------------------------- #

    @contextmanager
    def _materialize(self, ctx: AnalysisContext, prefix: str = "malaz_die_"):
        # The suffix can come from an archive member name (untrusted): left
        # uncapped it pushes the temp path past the Windows 260-char limit,
        # mkstemp raises, and _die() degrades to a weight-0 DIE_ERROR —
        # silently disabling the whole DIE stage (measured: a packed sample
        # drops from score 50/RED to 20/YELLOW). Same guard as clamav.py,
        # windows_av.py and office_pipeline.py.
        suffix = safe_temp_suffix(ctx.path.suffix)
        fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(ctx.data)
            yield tmp_path
        finally:
            with suppress(OSError):
                os.unlink(tmp_path)

    def _die(self, ctx: AnalysisContext) -> list[Indicator]:
        """Optional DIE stage: packer/compiler/protector identification."""
        if config.DIE_SKIP_SIGNED and authenticode_status(ctx) == "Valid":
            # Measured: DIE costs ~0.6 s per PE. A validly signed Microsoft
            # binary is still statically analysed by YARA/PE/entropy; the
            # packer-identification subprocess adds little there. Unsigned or
            # tampered files (the interesting case) still run DIE.
            return []
        scanner = DieScanner()
        if not scanner.available:
            return []
        binary = getattr(scanner, "binary", None)
        try:
            binary_mtime = binary.stat().st_mtime_ns if binary else 0
        except OSError:
            binary_mtime = 0
        digest = ctx.sha256 or hashlib.sha256(ctx.data).hexdigest()
        cache_key = (
            digest,
            type(scanner).__name__,
            str(binary),
            binary_mtime,
            getattr(scanner, "timeout", None),
        )
        with _DIE_CACHE_LOCK:
            cached = _DIE_CACHE.get(cache_key)
            if cached is not None:
                _DIE_CACHE.move_to_end(cache_key)
        if cached is not None:
            return self._die_indicators(cached)
        try:
            with self._materialize(ctx) as tmp:
                result = scanner.scan_path(tmp)
        except Exception as exc:
            return [
                self._indicator(
                    "DIE_ERROR",
                    "DIE-Scan fehlgeschlagen",
                    detail=f"{type(exc).__name__}: {exc}",
                    severity=Severity.INFO,
                    category=CAT_RESOURCE,
                    weight=0,
                )
            ]
        if not result.scanned:
            # NICHT GEPRUEFT IST NICHT SAUBER. DIE_PACKER/PROTECTOR/CRYPTOR
            # sind die einzigen 30-Punkte-Quellen dieser Stufe; das Projekt hat
            # den Verlust selbst gemessen ("packed sample drops from score
            # 50/RED to 20/YELLOW"). Der capa-Geschwisterpfad wurde fuer genau
            # diesen Fall sichtbar gemacht (CAPA_SKIPPED) — hier fehlte es.
            # Gewicht 0: eine nicht gelaufene Stufe ist der Datei nicht
            # anzulasten, aber sie muss SICHTBAR sein.
            grund = getattr(result, "skipped_reason", "") or "unbekannter Grund"
            return [
                self._indicator(
                    "DIE_SKIPPED",
                    "DIE-Stufe nicht gelaufen",
                    detail=(
                        f"{grund} — Packer-/Protector-Erkennung hat diese Datei "
                        "NICHT geprüft. Ein gepacktes Programm bliebe hier "
                        "unauffällig."
                    ),
                    severity=Severity.INFO,
                    category=CAT_RESOURCE,
                    weight=0,
                )
            ]
        findings = tuple(dict(finding) for finding in result.findings)
        with _DIE_CACHE_LOCK:
            _DIE_CACHE[cache_key] = findings
            _DIE_CACHE.move_to_end(cache_key)
            while len(_DIE_CACHE) > _DIE_CACHE_MAX:
                _DIE_CACHE.popitem(last=False)
        return self._die_indicators(findings)

    def _die_indicators(self, findings) -> list[Indicator]:
        out: list[Indicator] = []
        for finding in findings:
            ftype = str(finding.get("type") or "?")
            name = str(finding.get("name") or "?")
            if name.lower() in ("unknown", "?") or ftype.lower() in ("unknown", "?"):
                continue  # "nothing detected" is not a finding
            weight = finding_risk(finding)
            version = finding.get("version") or ""
            label = f"{ftype}: {name}" + (f" {version}" if version else "")
            severity = (
                Severity.HIGH if weight >= 30
                else Severity.MEDIUM if weight >= 10
                else Severity.INFO
            )
            out.append(
                self._indicator(
                    f"DIE_{ftype.upper().replace(' ', '_')}",
                    f"Detect It Easy: {label}",
                    detail=(
                        "Packer/Compiler-Identifikation durch DIE (nur Format-"
                        "Erkennung, keine AV-Bewertung)."
                    ),
                    severity=severity,
                    category=CAT_FORMAT,
                    weight=weight,
                )
            )
        return out

    # -- stage 6: capa (Fähigkeiten) ---------------------------------------- #

    def _capa(self, ctx: AnalysisContext) -> list[Indicator]:
        """Optionale capa-Stufe: was KANN dieses Programm?

        Anders als DIE (Format, Packer) nennt capa Fähigkeiten in ganzen
        Sätzen. Die Meldung ist bewusst EINE je Datei: die Namen sind der
        Inhalt, nicht 200 einzelne Befunde — ein Befund je Regel würde den
        Score mit einem Vielfachen von 15 fluten (dieselbe Fähigkeit feuert auf
        jedem legitimen Programm).
        """
        level, weight = _CAPA_LEVELS["CAPA_UNAVAILABLE"]
        if not config.CAPA_ENABLED:
            # ABSICHTLICH aus — das ist eine ANDERE Aussage als "capa fehlt",
            # und sie muss auch anders heissen. Alles ist installiert, der
            # Nutzer hat die Analyse nur nicht eingeschaltet; der Hinweis
            # nennt den Schalter und den Grund (gemessen 23 bis 600+ Sekunden
            # je Programm).
            return [
                self._indicator(
                    "CAPA_UNAVAILABLE",
                    _CAPA_TITLES["CAPA_UNAVAILABLE"],
                    detail=_capa_disabled_hint(),
                    severity=level,
                    category=CAT_RESOURCE,
                    weight=weight,
                )
            ]
        scanner = CapaScanner()
        if not scanner.available:
            return [
                self._indicator(
                    "CAPA_UNAVAILABLE",
                    _CAPA_TITLES["CAPA_UNAVAILABLE"],
                    detail=(
                        "capa ist nicht installiert — die Fähigkeits-Analyse "
                        "(„was kann dieses Programm?“) entfällt. Reine "
                        "Diagnose: kein Erkennungsverlust, alle anderen Stufen "
                        "laufen unverändert. Die Binary wird nicht "
                        "mitgeliefert (Apache-2.0, Installation wie bei DIE/"
                        "ClamAV/7-Zip durch den Nutzer)."
                    ),
                    severity=level,
                    category=CAT_RESOURCE,
                    weight=weight,
                )
            ]
        try:
            with self._materialize(ctx, prefix="malaz_capa_") as tmp:
                result = scanner.scan_path(tmp)
        except Exception as exc:
            level, weight = _CAPA_LEVELS["CAPA_ERROR"]
            return [
                self._indicator(
                    "CAPA_ERROR",
                    _CAPA_TITLES["CAPA_ERROR"],
                    detail=f"{type(exc).__name__}: {exc}",
                    severity=level,
                    category=CAT_RESOURCE,
                    weight=weight,
                )
            ]
        if not result.scanned and not result.understood:
            # NICHT still — aber nur, wenn die Stufe wirklich nicht laufen
            # KONNTE. ``scanned=False`` allein sagt das nicht: ein Lauf ohne
            # Treffer landet im selben Zweig und setzt ``understood=True``.
            # Ohne diese Unterscheidung stuende auf jedem gepackten PE "capa
            # konnte nicht laufen".
            #
            # Gemeldet wird also: Regelbasis fehlt (Returncode 10), Timeout,
            # Uebergroesse, unlesbare Ausgabe — und der wahrscheinlichste
            # Installationsweg trifft den ersten Fall.
            # ``pip install flare-capa`` bringt keinen ``rules/``-Ordner mit,
            # capa bricht mit rc 10 ab, ``_missing_rules_hint()`` baut eine
            # hilfreiche Meldung — die wurde hier weggeworfen. Der Nutzer sah
            # keine capa-Zeile und las das als "capa lief, nichts gefunden".
            #
            # Dieselbe Begruendung wie bei CAPA_ERROR: eine Stufe, die nicht
            # laufen konnte, wird GEMELDET, nicht verschwiegen. Gewicht 0 —
            # es ist eine Konfigurationsdiagnose, kein Erkennungsverlust.
            level, weight = _CAPA_LEVELS["CAPA_SKIPPED"]
            return [
                self._indicator(
                    "CAPA_SKIPPED",
                    _CAPA_TITLES["CAPA_SKIPPED"],
                    detail=(result.skipped_reason or "capa lieferte kein Ergebnis")
                    + (f" — {result.detail}" if result.detail else ""),
                    severity=level,
                    category=CAT_RESOURCE,
                    weight=weight,
                )
            ]
        if not result.capabilities:
            # "keine Fähigkeiten erkannt" ist der Regelfall bei gepackten oder
            # unbekannten Formaten — kein Befund, kein Score, keine Meldung.
            return []
        # Die Faehigkeiten strukturiert am Ergebnis ablegen: der Reiter zeigt
        # sie gruppiert und erklaert, was eine Semikolon-Zeile im Befundtext
        # nicht leistet.
        # BEIDE Formen: ``display`` traegt den deutschen Namensraum als
        # Praefix und gehoert in den Befundtext ("Verstecken vor Analyse:
        # detect debugger"). Der Reiter gruppiert aber NACH dem Namensraum —
        # dort waere dasselbe Praefix an jedem Eintrag redundant, er nimmt
        # deshalb ``name``.
        ctx.capa_capabilities = [
            {"name": rule.name, "display": rule.display, "namespace": rule.namespace}
            for rule in result.capabilities
        ]
        level, weight = _CAPA_LEVELS["CAPA_CAPABILITY"]
        return [
            self._indicator(
                "CAPA_CAPABILITY",
                _CAPA_TITLES["CAPA_CAPABILITY"],
                detail=_capa_detail(result),
                severity=level,
                category=CAT_CONTENT,
                weight=weight,
            )
        ]
