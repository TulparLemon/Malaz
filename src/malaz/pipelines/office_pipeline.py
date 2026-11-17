"""Office & Excel analysis pipeline.

1. OLE triage & VBA (oletools olevba/oleid) — macros, auto-exec triggers,
   suspicious API calls.
2. DDE link detection (oletools msodde).
3. Excel 4.0 XLM emulation (XLMMacroDeobfuscator) — deobfuscates XLM formulas
   such as ``EXEC``/``CALL`` in an isolated emulator (no real execution).
4. Formula analysis (openpyxl) — dangerous cell functions in ``.xlsx``.

All third-party tools are invoked on a temporary copy of the bytes; nothing is
ever executed. Every stage degrades gracefully when its library is missing.
"""

from __future__ import annotations

import io
import logging
import os
import queue
import re
import tempfile
import threading
import zipfile
from contextlib import contextmanager, suppress

from .. import config
from ..core.ole_depth import (
    directory_frames as _ole_directory_frames,
)
from ..core.ole_depth import (
    directory_too_deep as _ole_directory_too_deep,
)
from ..core.ole_depth import walk_headroom as _ole_walk_headroom
from ..core.ooxml_rels import external_relationships
from ..core.script_deobf import extract_vba_strings
from ..models import (
    CAT_FORMAT,
    CAT_IOC,
    CAT_MACRO,
    CAT_METADATA,
    CAT_SCRIPT,
    AnalysisContext,
    Indicator,
    Severity,
)
from ..procio import safe_temp_suffix
from .base import Pipeline


def _try_unlink(path) -> None:
    """Best-effort delete (delayed XLM temp-file cleanup; str from mkstemp)."""
    with suppress(OSError):
        os.unlink(path)


# ``[Content_Types].xml`` is the authoritative mapping part name -> parser.
# openpyxl resolves shared strings through it (openpyxl/reader/excel.py), so a
# guard that only looks at file NAMES is bypassed by renaming the part (audit
# SEC-016). The map is small in every real package; the read is bounded.
_CONTENT_TYPES_NAME = "[content_types].xml"
_CONTENT_TYPES_MAX_BYTES = 512 * 1024
_CONTENT_TYPE_ENTRY_RE = re.compile(r"<(?:Override|Default)\b[^>]{0,4096}>", re.IGNORECASE)
_CONTENT_TYPE_ATTR_RE = re.compile(
    r"""\b(PartName|ContentType|Extension)\s*=\s*(?:"([^"]{0,512})"|'([^']{0,512})')""",
    re.IGNORECASE,
)
_XML_CONTENT_TYPES = frozenset({"application/xml", "text/xml"})


def _xml_parts_from_content_types(archive: zipfile.ZipFile) -> tuple[set[str], set[str]]:
    """``(part names, extensions)`` declared as XML in ``[Content_Types].xml``.

    Returns empty sets when the map is missing or unreadable — the caller then
    falls back to the ``.xml`` suffix, which is still checked. A crafted map
    can only ADD parts to the guard, never remove the suffix rule.
    """
    info = next(
        (i for i in archive.infolist() if i.filename.lower() == _CONTENT_TYPES_NAME),
        None,
    )
    if info is None or info.file_size > _CONTENT_TYPES_MAX_BYTES:
        return set(), set()
    try:
        with archive.open(info) as handle:
            raw = handle.read(_CONTENT_TYPES_MAX_BYTES)
    except Exception:
        return set(), set()
    text = raw.decode("utf-8", "replace")
    parts: set[str] = set()
    extensions: set[str] = set()
    for entry in _CONTENT_TYPE_ENTRY_RE.finditer(text):
        attrs: dict[str, str] = {}
        for attr in _CONTENT_TYPE_ATTR_RE.finditer(entry.group(0)):
            value = attr.group(2) if attr.group(2) is not None else attr.group(3) or ""
            attrs[attr.group(1).lower()] = value.strip()
        content_type = attrs.get("contenttype", "").lower()
        if not (content_type.endswith("+xml") or content_type in _XML_CONTENT_TYPES):
            continue
        if "partname" in attrs:
            parts.add(attrs["partname"].lower().lstrip("/"))
        elif "extension" in attrs:
            extensions.add(attrs["extension"].lower().lstrip("."))
    return parts, extensions


def _ooxml_bomb_guard(blob: bytes) -> str | None:
    """Apply the archive-stage bomb rule to an OOXML container.

    ``openpyxl`` parses the shared-strings part completely before the first
    cell is read, so ``MAX_FORMULA_CELLS`` cannot bound the cost of a crafted
    workbook: measured, a 132 KB ``.xlsx`` whose member declares 128 MiB made
    the loader allocate ~256 MiB and spend ~1-13 s, without a single indicator.
    The declared sizes are therefore checked here first — the same rule the
    archive stage applies per member (``core/archive.py``).

    The size cap is applied to EVERY XML part, not to two hard-coded names:
    openpyxl finds shared strings and worksheets through ``[Content_Types].xml``,
    so ``xl/evil/strings.xml`` with the sharedStrings content type was parsed
    in full while a name check saw nothing (audit SEC-016). Parts declared as
    XML in the content-type map and every ``.xml`` member are covered.

    Returns the reason to refuse, or ``None`` if the container may be parsed.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            infos = zf.infolist()
            xml_parts, xml_extensions = _xml_parts_from_content_types(zf)
    except Exception:
        # Not a readable zip: let openpyxl report the parse failure, exactly as
        # before (OFFICE_FORMULA_PARSE_WARN).
        return None
    total = 0
    for info in infos:
        name = info.filename.lower().lstrip("/")
        extension = name.rsplit(".", 1)[-1] if "." in name else ""
        is_xml_part = (
            name.endswith(".xml")
            or name in xml_parts
            or (extension and extension in xml_extensions)
        )
        if is_xml_part and info.file_size > config.MAX_FORMULA_MEMBER_SIZE:
            return (
                f"Eintrag {info.filename} zu groß ({info.file_size} Bytes > "
                f"{config.MAX_FORMULA_MEMBER_SIZE}) — nicht entpackt."
            )
        if info.file_size > config.MAX_EXTRACTED_FILE_SIZE:
            return (
                f"Eintrag {info.filename} zu groß ({info.file_size} Bytes > "
                f"{config.MAX_EXTRACTED_FILE_SIZE}) — nicht entpackt."
            )
        total += info.file_size
    if total > config.MAX_UNCOMPRESSED_SIZE:
        return (
            f"Entpacktes Gesamtvolumen {total} Bytes überschreitet das Limit "
            f"{config.MAX_UNCOMPRESSED_SIZE} (Zip-Bomben-Schutz)."
        )
    return None


def _container_readable(blob: bytes, detected_type: str) -> bool:
    """Is the container itself readable (per input route)?

    A stage failure whose cause is an unreadable container is *already*
    reported with weight 25 by the dispatcher — ``MAIL_CONTAINER_WARN`` for
    OLE (built from the very same ``probe_outlook_msg`` used here), the
    nameless ``ARCH_ZIP_ERROR``/``CORE_ERROR`` container note for archives.
    "Eine Ursache, eine gewichtete Aussage": the stage message must then stay a
    weight-0 diagnosis, exactly like ``ARCH_BADZIP`` in the archive pipeline
    (see its comment and
    ``tests/test_archive.py::test_corrupt_zip_keeps_the_weighted_unchecked_note``).
    A failure on a *readable* container is the stage's own news and has to be
    weighted — measured: a .docx with a truncated ``word/document.xml`` scans
    GREEN 0 while msodde throws, with no other indicator in the scan.

    Unknown situations answer ``True`` (the failure stays weighted): missing a
    weighted statement is the worse error, a duplicate is the recoverable one.
    """
    if detected_type == "ole":
        try:
            from ..core.mail_view import probe_outlook_msg
        except Exception:  # pragma: no cover - olefile ships with oletools
            return True
        try:
            return probe_outlook_msg(blob)[1] == ""
        except Exception:  # pragma: no cover - defensive
            return True
    if detected_type == "zip":
        # Same operation the archive stage performs before it hands members on
        # (core/archive.py via zipfile): if the central directory is gone, the
        # dispatcher's container note already carries the weight.
        try:
            zipfile.ZipFile(io.BytesIO(blob)).close()
            return True
        except Exception:
            return False
    return True


def _vba_project_found(parser) -> bool:
    """Did the library find a real MS-OVBA project (not just a byte pattern)?

    ``detect_vba_macros()`` is broader than the project list: olevba sets that
    flag for any stream containing the byte pattern ``b'Attribut\\x00'`` as well
    (the source comments it as "happens in some malformed files"), and it is
    called *after* ``find_vba_projects()`` may already have answered "no". A
    plain German sentence therefore reads as "VBA project detected": measured
    on a Word-97 container without any project whose ``WordDocument`` stream
    holds "Das Attribut\\x00 des Datensatzes wurde geprueft." —
    ``detect_vba_macros() == True`` while ``find_vba_projects() == 0``. Charging
    the "ungeprüft" statement on that turned a benign document YELLOW 40
    instead of GREEN 15 (the previous round's verdict). Only the project list
    (``PROJECT`` + ``VBA/_VBA_PROJECT`` + ``VBA/dir``) is the "detected" this
    statement claims.

    For an OpenXML container the top-level parser has no ``ole_file`` and
    answers ``None``; its projects live in ``ole_subfiles``, the same objects
    ``extract_macros`` recurses into. Asking the top level only would turn the
    intended case (project present, export empty) into a silent loss for
    .docm/.xlsm — measured: a .docm whose embedded ``vbaProject.bin`` has a
    truncated ``dir`` stream reports ``find_vba_projects() is None`` at the top
    level and one project per subfile.

    Unknown answers ``True``: a missing weighted statement is the worse error,
    a duplicate the recoverable one (same rule as :func:`_container_readable`).
    """
    candidates = [parser]
    candidates.extend(getattr(parser, "ole_subfiles", None) or ())
    for candidate in candidates:
        try:
            if candidate.find_vba_projects():
                return True
        except Exception:  # pragma: no cover - defensive; unreadable stays weighted
            return True
    return False


def _xlm_applicable(blob: bytes) -> bool:
    """Does this container hold a workbook the emulator could evaluate?

    For OLE, ``xlrd2`` — the reader inside XLMMacroDeobfuscator — looks for a
    stream named ``Workbook``/``Book`` and raises ``XLRDError("Can't find
    workbook in OLE2 compound document")`` when there is none. That is *not
    applicable*, not *not checked*: whatever Excel 4.0 macro might want to
    run, a container without a workbook cannot carry one (measured: a harmless
    Word document renamed to ``.xls`` scores GREEN 0; with a blanket weight of
    25 it turned YELLOW 25 with exactly that XLRDError — an over-correction on
    a benign artifact the corpora do not contain).

    For a zip (real ``.xlsm``/``.xlsb``) the emulator's ``XLSMWrapper``/
    ``XLSBWrapper`` needs the workbook part ``xl/workbook.xml`` resp.
    ``xl/workbook.bin``; a renamed ``.docx`` has neither and is likewise *not
    applicable*. Everything else — a corrupt or encrypted workbook, an
    emulator crash, an unreadable container — keeps the weighted message.
    Unknown answers ``True`` (weighted).
    """
    if zipfile.is_zipfile(io.BytesIO(blob)):
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                names = {info.filename.lower() for info in archive.infolist()}
        except Exception:  # pragma: no cover - defensive; unreadable stays weighted
            return True
        return "xl/workbook.xml" in names or "xl/workbook.bin" in names
    try:
        import olefile
    except Exception:  # pragma: no cover - olefile ships with oletools
        return True
    try:
        with olefile.OleFileIO(io.BytesIO(blob)) as ole:
            return bool(ole.exists("Workbook") or ole.exists("Book"))
    except Exception:  # pragma: no cover - defensive; unreadable stays weighted
        return True


# Endungen, für die die XLM-Emulation zuständig ist. Die Liste ist eine
# Format-Aussage, keine Container-Aussage: eine echte ``.xlsm``/``.xlsb`` ist
# ein ZIP, eine ``.xls`` ein OLE-Container — beide müssen die Stufe erreichen.
# Vorher stand hier nur ``detected_type == "ole"``; damit war der Eintrag
# ``.xlsm`` für jede echte .xlsm toter Code und eine XLM-only-Arbeitsmappe
# blieb GRÜN.
_XLM_SUFFIXES = (".xls", ".xlsm", ".xlsb", ".xlt", ".xla", ".xlam")
_XLM_CONTAINERS = ("ole", "zip")

# Ein XLM-Makroblatt liegt in OOXML unter ``xl/macrosheets/`` (XML) bzw.
# ``xl/macrosheets/*.bin`` (xlsb). Der Pfad ist die einzige Stelle, an der der
# Container die Existenz eines Makroblatts ohne Emulation verrät.
_XLM_MACROSHEET_MEMBER = re.compile(
    r"^xl/macrosheets/[^/]+\.(?:xml|bin)$", re.IGNORECASE
)


def _xlm_stage_enabled(ctx: AnalysisContext) -> bool:
    """Does :meth:`OfficePipeline.analyze` run the XLM stage for this file?"""
    return (
        ctx.detected_type in _XLM_CONTAINERS
        and ctx.path.suffix.lower() in _XLM_SUFFIXES
    )


def _xlm_macrosheet_present(blob: bytes, ole_file=None) -> bool:
    """Does the container carry an Excel-4.0 macro sheet (without emulating)?

    Zip: the macrosheet part lives at ``xl/macrosheets/…`` and is referenced
    from the workbook with the ``xlMacrosheet`` relationship.

    OLE/BIFF: the BOUNDSHEET record carries the sheet type; oletools' own
    ``plugin_biff`` (the parser ``olevba`` uses for this) prints
    ``Excel 4.0 macro sheet`` for type 1. ``ole_file`` is the already-open
    ``olefile`` handle of the caller's ``VBA_Parser`` — the stage must not
    open the same container a second time (the walk-headroom guarantee covers
    one handle).

    Unknown/unreadable answers ``False``: this predicate only adds a finding
    for a *detected* macrosheet, it is not the "stage did not run" statement
    (that one is already covered by the XLM stage's own warnings).
    """
    if zipfile.is_zipfile(io.BytesIO(blob)):
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                return any(
                    _XLM_MACROSHEET_MEMBER.match(info.filename)
                    for info in archive.infolist()
                )
        except Exception:  # pragma: no cover - defensive
            return False
    if ole_file is None:
        return False
    try:
        from oletools.thirdparty.oledump.plugin_biff import cBIFF

        for stream_name in ("Workbook", "Book"):
            if not ole_file.exists(stream_name):
                continue
            with ole_file.openstream(stream_name) as handle:
                stream = handle.read()
            lines = cBIFF(
                name=[stream_name], stream=stream, options="-o BOUNDSHEET"
            ).Analyze()
            if "Excel 4.0 macro sheet" in "\n".join(lines or ()):
                return True
    except Exception:  # pragma: no cover - nicht lesbar: kein Fund zu behaupten
        return False
    return False


def _ooxml_applicable(blob: bytes) -> bool:
    """Is this container a zip, i.e. could it hold an OOXML workbook?

    ``openpyxl`` can only check what a zip carries. A container that is no zip
    at all — a Word/Excel-97 document renamed to ``.xlsx`` — holds no workbook
    whose formulas could be checked: *not applicable*, not *not checked*. Same
    rule and same measured precedent as :func:`_xlm_applicable` (there: a
    harmless Word document renamed to ``.xls`` scored GREEN, and a blanket
    weight turned it YELLOW — an over-correction). Everything else — a readable
    zip whose XML the parser rejects — keeps the weighted message.
    """
    return zipfile.is_zipfile(io.BytesIO(blob))


# -- Verfasser-Angaben (nur Information, Gewicht 0) ------------------------- #
#
# Die Felder sind bewusst wenige und in Anzeige-Reihenfolge: Autor, Firma,
# zuletzt gespeichert von, Erzeuger, Vorlage. Links stehen die deutschen
# Beschriftungen, rechts die Schlüssel, unter denen die Quelle das Feld liefert
# (OOXML nennt es ``dc:creator``, die OLE-Property-Sets ``author``).
_METADATA_KEYS = (
    ("Autor", ("author", "creator")),
    ("Zuletzt gespeichert von", ("last_saved_by", "lastmodifiedby")),
    ("Firma", ("company",)),
    ("Erzeuger", ("creating_application", "application")),
    ("Vorlage", ("template",)),
)
# Ein Metadatenwert ist Freitext aus dem Dokument — begrenzt, damit eine
# präparierte Datei die Anzeige nicht flutet.
_METADATA_MAX_VALUE_CHARS = 200
_METADATA_MEMBER_BYTES = 256 * 1024

# Ein einfaches XML-Element mit optionalem Namensraum-Präfix. Beschränkte
# Quantoren: der Text stammt aus dem Dokument, ein unbeschränktes Muster würde
# bei vielen ``<`` quadratisch. Nur flache Blätter (core.xml/app.xml) werden
# gebraucht, deshalb kein echter XML-Parser — weniger Angriffsfläche als
# Entitäten-Expansion.
_SIMPLE_XML_ELEMENT = re.compile(
    r"<(?:[A-Za-z0-9_]{1,32}:)?([A-Za-z0-9_]{1,64})\b[^>]{0,300}>"
    r"([^<]{0,1000})</(?:[A-Za-z0-9_]{1,32}:)?\1>"
)
# Die fünf in XML vordefinierten Entitäten; mehr kann in einem Elementtext
# nicht vorkommen (eigene Entities wären ein Angriff und werden nicht aufgelöst).
_XML_ENTITIES = (
    ("&lt;", "<"),
    ("&gt;", ">"),
    ("&quot;", '"'),
    ("&apos;", "'"),
    ("&amp;", "&"),
)


def _xml_unescape(text: str) -> str:
    """Die fünf vordefinierten XML-Entitäten auflösen (Reihenfolge: ``&amp;`` zuletzt)."""
    for entity, char in _XML_ENTITIES:
        text = text.replace(entity, char)
    return text


def _ooxml_metadata(data: bytes) -> dict[str, str]:
    """Verfasser-Angaben aus ``docProps/core.xml`` und ``docProps/app.xml``.

    Schlüssel sind die kleingeschriebenen Elementnamen (``creator``,
    ``lastmodifiedby``, ``company``, ``application``, ``template``). Ein
    nicht lesbares Mitglied oder ein Nicht-Zip liefert schlicht keine Werte —
    „unlesbar" meldet die Container-Stufe des Scans.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return {}
    values: dict[str, str] = {}
    try:
        with archive:
            for member in ("docProps/core.xml", "docProps/app.xml"):
                try:
                    info = archive.getinfo(member)
                except KeyError:
                    continue
                if info.file_size > _METADATA_MEMBER_BYTES:
                    continue
                try:
                    text = archive.read(info).decode("utf-8", errors="replace")
                except Exception:
                    continue
                for name, raw in _SIMPLE_XML_ELEMENT.findall(text):
                    key = name.lower()
                    if key in values:
                        continue
                    value = _xml_unescape(raw).strip()
                    if value:
                        values[key] = value
    except Exception:
        return values
    return values


def _ole_metadata(data: bytes) -> dict[str, str]:
    """Verfasser-Angaben aus den OLE-Property-Sets (``.doc``/``.xls``).

    ``olefile`` liest ``\\x05SummaryInformation``/``\\x05DocumentSummaryInformation``
    und legt sie als :class:`olefile.OleMetadata` ab — genau die Felder, die
    Word/Excel im Datei-Dialog „Eigenschaften" zeigen.
    """
    try:
        import olefile
    except Exception:  # pragma: no cover - olefile ships with oletools
        return {}
    # Der Kopfraum-Schutz ist hier PFLICHT, nicht Beiwerk: olefile laeuft die
    # Verzeichnisstruktur rekursiv ab, und ein Angreifer bestimmt mit einem
    # 128-Byte-Eintrag je Ebene die Tiefe. Ohne den Schutz stirbt die Stufe mit
    # RecursionError — genau der Fall, den core/ole_depth fuer die VBA-Stufe
    # bereits abfaengt. Diese neue Stelle hatte ihn nicht; gefunden hat das der
    # Waechter-Test test_every_olefile_call_site_is_inside_the_headroom, der
    # genau dafuer existiert.
    frames = _ole_directory_frames(data)
    if frames is not None and _ole_directory_too_deep(frames):
        # Zu tief: nicht lesen. Die Metadaten sind eine Information mit
        # Gewicht 0 — dafuer lohnt kein Risiko.
        return {}
    try:
        with (
            _ole_walk_headroom(frames if frames is not None else 0),
            olefile.OleFileIO(io.BytesIO(data)) as ole,
        ):
            meta = ole.get_metadata()
    except Exception:
        return {}
    values: dict[str, str] = {}
    for key in ("author", "last_saved_by", "company", "creating_application", "template"):
        raw = getattr(meta, key, None)
        if raw is None:
            continue
        text = str(raw).strip()
        if text:
            values[key] = text
    return values


# Die Ergebnis-Typen, unter denen olevba dekodierte Zeichenketten meldet:
# kodierte Blöcke (Hex/Base64/Dridex) und VBA-Ausdrücke (Chr-Verkettung). Der
# jeweils zweite Wert des Tupels ist die LESBARE Form.
_DECODED_STRING_KINDS = ("Hex String", "Base64 String", "Dridex string", "VBA string")
# Kürzere Treffer sind Rauschen (ein einzelnes Zeichen, ein Zahlenrest).
_MIN_DECODED_CHARS = 4


def _decoded_macro_strings(parser, raw_lower: str) -> list[str]:
    """Vom olevba-Decoder sichtbar gemachte Makro-Zeichenketten (``--decode``).

    ``analyze_macros(show_decoded_strings=True)`` ist die Bibliotheks-API hinter
    dem ``--decode`` der Kommandozeile; ``VBA_Parser.reveal`` existiert zwar,
    ersetzt in der geprüften Version (olevba 0.60.2) aber nur ``VBA string``
    und damit nichts, solange ``deobfuscate`` nicht gesetzt ist. Zurückgegeben
    wird nur, was im Roh-Quelltext NICHT vorkommt — eine Dekodierung, die
    denselben Text liefert, ist keine neue Erkenntnis. Fehlt die API, bleibt es
    bei der leeren Liste.
    """
    if not hasattr(parser, "analyze_macros"):
        return []
    try:
        analysis = parser.analyze_macros(show_decoded_strings=True)
    except Exception:
        return []
    decoded: list[str] = []
    for entry in analysis or ():
        if len(entry) != 3:
            continue
        kind, value, _encoded = entry
        if kind not in _DECODED_STRING_KINDS:
            continue
        text = str(value).strip()
        if len(text) < _MIN_DECODED_CHARS:
            continue
        if text.lower() in raw_lower or text in decoded:
            continue
        decoded.append(text)
    return decoded


_AUTOEXEC_TRIGGERS = (
    "autoopen",
    "auto_open",
    "workbook_open",
    "document_open",
    "autoexec",
    "auto_close",
    "workbook_beforeclose",
    "auto_new",
    "document_close",
)

_SUSPICIOUS_APIS = (
    "shell",
    "wscript.shell",
    "createobject",
    "urldownloadtofile",
    "winexec",
    "callbyname",
    "powershell",
    "cmd.exe",
    "adodb.stream",
    "scripting.filesystemobject",
    "net.webclient",
    "invoke-expression",
    "environ",
    "shellapplication",
    "xmlhttp",
    "msxml2.xmlhttp",
)

# Markers that, when reassembled from obfuscated VBA but absent from the raw
# code, reveal a hidden payload (download URLs etc. on top of the API list).
_OBFUSCATION_MARKERS = (
    *_SUSPICIOUS_APIS,
    "http://",
    "https://",
    "ftp://",
)

# Behavioral macro patterns (purely static). Each entry is
# (rule_id, label, severity, weight, keyword-groups); a pattern fires when at
# least one keyword from EVERY group is present, so multi-group patterns describe
# a chain (e.g. download AND execute), which keeps false positives low.
_VBA_BEHAVIOR_PATTERNS = (
    (
        "OFFICE_VBA_DL_EXEC",
        "Download-&-Execute-Kette",
        Severity.CRITICAL,
        50,
        (
            ("urldownloadtofile", "net.webclient", "xmlhttp", "winhttp.request",
             "invoke-webrequest", "downloadfile", "downloadstring", "urlcache"),
            ("shell", "wscript.shell", "createobject", ".run", ".exec",
             "winexec", "shellexecute", "callbyname"),
        ),
    ),
    (
        "OFFICE_VBA_ENC_PS",
        "Encodierter PowerShell-Aufruf",
        Severity.HIGH,
        30,
        (
            ("-encodedcommand", "-enc ", "frombase64string",
             "[convert]::frombase64string"),
        ),
    ),
    (
        "OFFICE_VBA_LOLBIN",
        "LOLBin-Missbrauch",
        Severity.HIGH,
        30,
        (
            ("regsvr32", "mshta", "rundll32", "certutil", "wmic ",
             "installutil", "msbuild", "odbcconf"),
        ),
    ),
    (
        "OFFICE_VBA_PERSIST",
        "Persistenz-Mechanismus",
        Severity.HIGH,
        30,
        (
            ("currentversion\\run", "currentversion\\runonce", "\\startup\\",
             "schtasks /create"),
        ),
    ),
)


log = logging.getLogger(__name__)


class OfficePipeline(Pipeline):
    name = "office"

    def analyze(self, ctx: AnalysisContext) -> list[Indicator]:
        indicators: list[Indicator] = []
        suffix = ctx.path.suffix.lower()
        # ONE measurement of the container's directory depth for the whole run.
        # olefile traverses that tree recursively, so this single file property
        # decides which of the stages below can run — they must not each
        # re-derive it. Measured: one contentless container with 496 storages
        # reached RED 100 through four 25s (VBA_STOP + DDE + XLM + the
        # dispatcher's MAIL_CONTAINER_WARN) — four weighted statements for one
        # cause ("eine Ursache, eine gewichtete Aussage"), and the verdict
        # turned on how many olefile users happened to die together rather than
        # on content.
        depth_frames = _ole_directory_frames(ctx.data)
        try:
            # ONE temp file for every stage below: the tools need a real path,
            # and the stages run strictly one after another (olevba's parser is
            # closed before DDE starts). Before this, each stage wrote the same
            # bytes again — measured on the corpus: a .msg produced four temp
            # files, a .xls three.
            # One headroom window for all three stages: they all drive olefile's
            # recursive directory walk, and the depth was measured once above.
            # Raising it per stage would repeat the estimate for no gain;
            # leaving it out is what made the walk depend on how deep the
            # caller happened to be.
            with self._materialize(ctx) as tmp, _ole_walk_headroom(depth_frames):
                indicators.extend(self._vba_analysis(ctx, tmp, depth_frames))
                indicators.extend(self._dde_analysis(ctx, tmp, depth_frames))
                if _xlm_stage_enabled(ctx):
                    indicators.extend(self._xlm_analysis(ctx, tmp, depth_frames))
        except OSError as exc:
            # No temp file: the three path-based stages cannot run. Say so
            # (INFO/0, the same class as their own stage warnings) instead of
            # failing the whole pipeline — an incomplete analysis must be
            # visible, never silent.
            indicators.append(
                self._indicator(
                    "OFFICE_STAGE_WARN",
                    "Office-Analyse unvollständig (keine Temp-Datei)",
                    detail=(
                        f"{type(exc).__name__}: {exc} — VBA-, DDE- und "
                        "XLM-Prüfung konnten nicht laufen."
                    ),
                    severity=Severity.INFO,
                    category=CAT_MACRO,
                    weight=0,
                )
            )
        # Reads ctx.data and needs no temp file: runs even when the stages
        # above could not.
        if suffix in (".xlsx", ".xlsm", ".xltm", ".xlam"):
            indicators.extend(self._formula_analysis(ctx))
        # Beide lesen nur ctx.data und brauchen keine Temp-Datei — sie laufen
        # deshalb auch dann, wenn die Stufen oben (z. B. mangels Temp-Datei)
        # nicht konnten. Die externen Beziehungen zuerst: sie sind ein Befund,
        # die Metadaten nur eine Information (Gewicht 0).
        indicators.extend(self._ooxml_rels_analysis(ctx))
        indicators.extend(self._metadata_analysis(ctx))
        return indicators

    # -- helpers ----------------------------------------------------------- #

    @contextmanager
    def _materialize(self, ctx: AnalysisContext):
        """Write the bytes to ONE temp file (tools need a real path).

        Used once per :meth:`analyze` run; the stages receive the path.
        """
        # The suffix can originate from an archive member name; sanitize it
        # centrally (ASCII-only, separators stripped, length capped) — an
        # over-long or illegal suffix made mkstemp fail and silently disabled
        # the whole VBA analysis.
        fd, tmp_path = tempfile.mkstemp(
            suffix=safe_temp_suffix(ctx.path.suffix), prefix="malaz_"
        )
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(ctx.data)
            yield tmp_path
        finally:
            with suppress(OSError):
                os.unlink(tmp_path)

    def _lib_fehlt(
        self, was: str, bibliothek: str, detail: str = ""
    ) -> list[Indicator]:
        """Ein Befund, wenn eine optionale Bibliothek fehlt — sichtbar, ohne Gewicht.

        GEMESSEN im Audit (Befund 6): vier Stufen fingen den fehlenden Import
        mit ``except: return []`` — ohne jeden Hinweis. Fehlt die Bibliothek
        (Teilinstallation, ``--no-deps``), ist ein makrotragendes .docm damit
        GRUEN, und niemand sieht, dass die Makro-Pruefung nie lief.

        Dieselbe Begruendung wie im Geschwister ``pdf_pipeline``: "eine Stufe,
        die nicht lief, ist GELB, nie gruen" (PDF_LIB_MISSING). Das Gewicht
        bleibt 0 — eine fehlende Bibliothek ist der DATEI nicht anzulasten —
        aber der Befund muss SICHTBAR sein. PE und PDF haben das seit jeher.
        """
        # BUG-103 (VM-Gegenprobe): a missing XLM library must not leave an
        # XLSM/XLS GREEN. Unlike a missing optional VBA/formula helper, the
        # XLM stage is the ONLY content check for an Excel-4.0 macrosheet;
        # "not run" is score-effective (MEDIUM/25) and stays in the
        # incomplete list. The VM build lacked the bundled library and a
        # synthetic XLM workbook scored GREEN 0 before this fix.
        ist_xlm = "XLM" in was
        return [
            self._indicator(
                "OFFICE_LIB_MISSING",
                f"Stufe nicht gelaufen: {was}",
                detail=(
                    f"Die Bibliothek '{bibliothek}' ist nicht verfügbar — "
                    f"{was} hat diese Datei NICHT geprüft. Ein Treffer darin "
                    "wäre unentdeckt geblieben."
                    + (f"\nUrsache: {detail}" if detail else "")
                ),
                severity=Severity.MEDIUM if ist_xlm else Severity.INFO,
                category=CAT_FORMAT,
                weight=25 if ist_xlm else 0,
            )
        ]

    def _xlm_unchecked_indicators(
        self, ctx: AnalysisContext, parser=None
    ) -> list[Indicator]:
        """XLM-Makroblätter im Container, aber die XLM-Stufe lief für ihn nicht.

        Regression BUG-024: ``detect_vba_macros()`` fragt nur nach
        ``vbaProject``; ein Arbeitsblatt mit Excel-4.0-Makros (``Auto_Open``,
        ``SET.NAME``/``EXEC``) liefert dort ``False``. Vorher endete die
        Makro-Stufe dann mit ``[]`` — auch dann, wenn die XLM-Stufe wegen
        Endung/Container gar nicht lief (etwa eine als ``.doc`` gespeicherte
        Makro-Arbeitsmappe). Existiert ein Makroblatt, ist das Ergebnis
        "nicht ausgewertet", nicht "sauber": gewichtete Meldung statt Stille.

        Läuft die XLM-Stufe für diese Datei (``_xlm_stage_enabled``), bleibt
        die Antwort leer: sie meldet ihr Ergebnis direkt danach selbst.
        ``parser`` liefert das bereits offene olefile-Handle; die Stufe darf
        den Container nicht ein zweites Mal öffnen.
        """
        if _xlm_stage_enabled(ctx):
            return []
        if not _xlm_macrosheet_present(
            ctx.data, getattr(parser, "ole_file", None)
        ):
            return []
        return [
            self._indicator(
                "OFFICE_XLM_PRESENT",
                "XLM-Makroblätter vorhanden — nicht ausgewertet",
                detail=(
                    "Der Container enthält mindestens ein Excel-4.0-Makroblatt "
                    f"(Endung {ctx.path.suffix or 'ohne'}, Containertyp "
                    f"{ctx.detected_type}). Für diese Kombination lief die "
                    "XLM-Emulation nicht, die Formeln wurden NICHT ausgewertet "
                    "— das Ergebnis ist unvollständig und nicht als 'sauber' "
                    "zu werten."
                ),
                severity=Severity.MEDIUM,
                category=CAT_MACRO,
                weight=25,
            )
        ]

    # -- stage 1: VBA / OLE ------------------------------------------------ #

    def _vba_analysis(
        self, ctx: AnalysisContext, tmp: str, depth_frames: int | None = None
    ) -> list[Indicator]:
        try:
            from oletools.olevba import VBA_Parser
        except Exception:
            return self._lib_fehlt("Makro-Analyse (VBA)", "oletools")

        # Cause: olefile walks the directory tree of the container recursively,
        # so an attacker-supplied nesting depth (one 128-byte directory entry
        # per level) decides whether the whole stage dies with RecursionError.
        # ``depth_frames`` is the ONE measurement from analyze() (iterative, no
        # recursion, no olefile); a direct caller without it measures here.
        #
        # The refusal is reported — a stage that cannot run is never silently
        # absent — but it is charged only ONCE. When the container itself is
        # already unreadable, the dispatcher's MAIL_CONTAINER_WARN carries 25
        # for exactly this cause (see _container_readable), so this message
        # stays a weight-0 diagnosis, the same rule as OFFICE_DDE_PARSE_WARN /
        # OFFICE_XLM_PARSE_WARN and ARCH_BADZIP. Measured before: a contentless
        # 496-storage container scored RED 50 (25 here + 25 there) — "bösartig"
        # for a file without a single content signal — instead of YELLOW 25 =
        # "ungeprüft".
        if depth_frames is None:
            depth_frames = _ole_directory_frames(ctx.data)
        if depth_frames is not None and _ole_directory_too_deep(depth_frames):
            already_reported = not _container_readable(ctx.data, ctx.detected_type)
            return [
                self._indicator(
                    "OFFICE_VBA_STOP",
                    "VBA-Analyse nicht möglich (OLE-Verzeichnis zu tief)",
                    detail=(
                        f"Der Verzeichnisbaum des Containers verlangt "
                        f"{depth_frames} Rekursions-Frames "
                        f"({depth_frames // 2} Storage-Ebenen) — olefile müsste "
                        "ihn rekursiv durchlaufen und bricht dabei mit "
                        "RecursionError ab. Die Makros wurden NICHT ausgewertet; "
                        "das Ergebnis ist unvollständig und nicht als 'sauber' "
                        "zu werten."
                        + (
                            " Ursache ist derselbe nicht lesbare Container, den "
                            "der Scan bereits mit Gewicht 25 meldet; diese "
                            "Meldung bleibt deshalb die Diagnose (welche Stufe "
                            "es gemerkt hat)."
                            if already_reported
                            else ""
                        )
                    ),
                    severity=Severity.INFO if already_reported else Severity.MEDIUM,
                    category=CAT_MACRO,
                    weight=0 if already_reported else 25,
                )
            ]

        # olevba reads whole container members into memory — for a .docx with
        # an OLE-magic member that is the member's full size (measured peak
        # 26 MiB at a 4 MiB member, 45 MiB at 16 MiB) and the only guard was
        # the formula stage, which a .docx never reaches (audit SEC-017). Run
        # the bomb rule before the library sees the bytes.
        if ctx.detected_type == "zip":
            # Only a container the dispatcher typed as ZIP is an OOXML
            # package. ``zipfile.is_zipfile`` is NOT the criterion: ``ZipFile``
            # tolerates arbitrary prepended bytes, so a .doc/.msg (OLE) with an
            # embedded ZIP would be inspected as a package and its VBA stage
            # refused for a member size that belongs to the inner archive.
            bomb_reason = _ooxml_bomb_guard(ctx.data)
            if bomb_reason is not None:
                return [
                    self._indicator(
                        "OFFICE_VBA_STOP",
                        "VBA-Analyse übersprungen (Bombenschutz)",
                        detail=(
                            f"{bomb_reason} Die Makros wurden NICHT ausgewertet "
                            "— das Ergebnis ist unvollständig und nicht als "
                            "'sauber' zu werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_MACRO,
                        weight=25,
                    )
                ]

        out: list[Indicator] = []
        try:
            parser = VBA_Parser(tmp)
            try:
                if not parser.detect_vba_macros():
                    return self._xlm_unchecked_indicators(ctx, parser)
                out.append(
                    self._indicator(
                        "OFFICE_MACRO",
                        "VBA-Makros vorhanden",
                        detail="Das Dokument enthält VBA-Makros.",
                        severity=Severity.MEDIUM,
                        category=CAT_MACRO,
                        weight=15,
                    )
                )

                autoexec_hits: set[str] = set()
                suspicious_hits: set[str] = set()
                macro_names: list[str] = []
                code_chunks: list[str] = []
                for _filename, _stream, vba_filename, vba_code in parser.extract_macros():
                    macro_names.append(vba_filename)
                    code_chunks.append(vba_code)
                    lowered = vba_code.lower()
                    for trigger in _AUTOEXEC_TRIGGERS:
                        if trigger in lowered:
                            autoexec_hits.add(trigger)
                    for api in _SUSPICIOUS_APIS:
                        if api in lowered:
                            suspicious_hits.add(api)

                # Result of the export, not the exception: the library swallows
                # its own failure. ``VBA_Project`` raises on an unreadable
                # ``dir`` stream (ValueError "invalid signature byte" /
                # UnexpectedDataError) and ``extract_macros`` catches that per
                # project (``except Exception: log.exception``) and yields
                # nothing, so no exception ever reaches the handler below.
                # Measured on the real macro document (real MS-OVBA streams,
                # AutoOpen + WScript.Shell) with only the compressed ``dir``
                # stream replaced (2048 zero bytes resp. truncated): the
                # project is still detected, the module stream is untouched,
                # and the scan scored GREEN 15 — the sole weighted indicator in
                # the whole scan was OFFICE_MACRO (15), 15 < SCORE_GREEN_MAX.
                # A detected project whose source was never read is
                # "ungeprüft", not "clean": same class and same weight as
                # OFFICE_VBA_STOP / OFFICE_VBA_WARN above, and like them it is
                # charged only once — for an unreadable container the
                # dispatcher's MAIL_CONTAINER_WARN already carries the 25.
                # The predicate is the project list, never ``detect_vba_macros()``
                # alone: that flag also fires for the raw byte pattern
                # ``b'Attribut\x00'``, which turned a benign German document
                # YELLOW 40 (see ``_vba_project_found``). A container without a
                # project has nothing to check — it is not "ungeprüft".
                if not macro_names and _vba_project_found(parser):
                    already_reported = not _container_readable(ctx.data, ctx.detected_type)
                    out.append(
                        self._indicator(
                            "OFFICE_VBA_WARN",
                            "Makro-Projekt erkannt, aber kein Quelltext ausgelesen",
                            detail=(
                                "find_vba_projects() meldet ein VBA-Projekt "
                                "(MS-OVBA-Gerüst aus PROJECT, VBA/_VBA_PROJECT und "
                                "VBA/dir), der Export lieferte jedoch kein "
                                "einziges Modul — der "
                                "Makro-Quelltext wurde NICHT ausgewertet (die "
                                "Bibliothek verschluckt den Parse-Fehler des "
                                "VBA-Verzeichnisses und liefert stillschweigend "
                                "nichts). Das Ergebnis ist unvollständig und nicht "
                                "als 'sauber' zu werten."
                                + (
                                    " Ursache ist derselbe nicht lesbare Container, den "
                                    "der Scan bereits mit Gewicht 25 meldet; diese "
                                    "Meldung bleibt deshalb die Diagnose (welche Stufe "
                                    "es gemerkt hat)."
                                    if already_reported
                                    else ""
                                )
                            ),
                            severity=Severity.INFO if already_reported else Severity.MEDIUM,
                            category=CAT_MACRO,
                            weight=0 if already_reported else 25,
                        )
                    )

                if autoexec_hits:
                    out.append(
                        self._indicator(
                            "OFFICE_AUTOEXEC",
                            "Auto-Exec-Trigger: " + ", ".join(sorted(autoexec_hits)),
                            detail="Makros werden beim Öffnen automatisch ausgeführt.",
                            severity=Severity.HIGH,
                            category=CAT_MACRO,
                            weight=30,
                        )
                    )
                if suspicious_hits:
                    # AutoExec + suspicious API together is the classic
                    # malicious-macro pattern -> critical (anchor).
                    combined = bool(autoexec_hits)
                    out.append(
                        self._indicator(
                            "OFFICE_SUSPICIOUS_API",
                            "Verdächtige API-Aufrufe: " + ", ".join(sorted(suspicious_hits)),
                            detail="Makro-Code nutzt APIs für Prozess-/Download-Ausführung.",
                            severity=Severity.CRITICAL if combined else Severity.HIGH,
                            category=CAT_SCRIPT,
                            weight=50 if combined else 30,
                        )
                    )

                # Deeper static analysis: reassemble obfuscated strings and
                # apply behavioral heuristics over the full macro code.
                combined_code = "\n".join(code_chunks)
                try:
                    reconstructed = extract_vba_strings(combined_code)
                except Exception:
                    reconstructed = []
                out.extend(
                    self._vba_deep_indicators(
                        combined_code.lower(), reconstructed, bool(autoexec_hits)
                    )
                )
                # olevba selbst dekodieren lassen (die API hinter ``--decode``):
                # Hex-/Base64-/Dridex-Ketten im Makro werden zu lesbaren
                # Zeichenketten. Die Meldung erscheint nur, wenn dabei etwas
                # NEUES herauskommt — sonst wiederholte sie nur, was der
                # Roh-Scan schon sieht.
                decoded = _decoded_macro_strings(parser, combined_code.lower())
                if decoded:
                    # Eigene ID neben OFFICE_VBA_OBFUSCATED: jene Regel
                    # (unten, _vba_deep_indicators) rekonstruiert Chr-/&-
                    # Verkettungen selbst; hier dekodiert die Bibliothek
                    # kodierte Blöcke. Zwei Techniken, zwei Meldungen — eine
                    # gemeinsame ID mit zwei Gewichten wäre nicht deutbar.
                    shown = " | ".join(item[:200] for item in decoded[:8])
                    out.append(
                        self._indicator(
                            "OFFICE_VBA_DECODED",
                            "Verschleierte Makro-Zeichenketten entschlüsselt",
                            detail=(
                                "olevba hat im Makro kodierte Zeichenketten "
                                "lesbar gemacht (rein statische Dekodierung, "
                                "nichts ausgeführt). Im sichtbaren Quelltext "
                                "standen sie nicht: " + shown
                            ),
                            severity=Severity.MEDIUM,
                            category=CAT_SCRIPT,
                            weight=15,
                        )
                    )
                out.extend(self._vba_stomping_indicators(parser))
                # Ein VBA-Projekt schließt eine XLM-Arbeitsmappe im selben
                # Container nicht aus (etwa eine .xlsm, die als .docm
                # gespeichert wurde): läuft die XLM-Stufe für diese Endung
                # nicht, bleibt das Makroblatt sonst ungeprüft und unsichtbar.
                out.extend(self._xlm_unchecked_indicators(ctx, parser))
            finally:
                parser.close()
        except RecursionError as exc:
            # Sink: the same failure the pre-check above prevents when it can
            # measure the container (this branch fires when the estimate said
            # the tree fits but the library's own stack did not). It must not
            # degrade to a weight-0 note — the macro path was not evaluated at
            # all, so the verdict for this document is "not checked", not
            # "clean" (weight like ARCH_MEMBER_STOP / MAIL_CONTAINER_WARN) —
            # and, like the pre-check, it is charged only once: for a container
            # that is unreadable anyway, MAIL_CONTAINER_WARN already carries
            # the 25 for the same cause.
            already_reported = not _container_readable(ctx.data, ctx.detected_type)
            out.append(
                self._indicator(
                    "OFFICE_VBA_STOP",
                    "VBA-Analyse nicht möglich (OLE-Verzeichnis zu tief)",
                    detail=(
                        f"{type(exc).__name__}: {exc} — der Makro-Pfad wurde "
                        "NICHT ausgewertet; das Ergebnis ist unvollständig und "
                        "nicht als 'sauber' zu werten."
                        + (
                            " Ursache ist derselbe nicht lesbare Container, den "
                            "der Scan bereits mit Gewicht 25 meldet; diese "
                            "Meldung bleibt deshalb die Diagnose."
                            if already_reported
                            else ""
                        )
                    ),
                    severity=Severity.INFO if already_reported else Severity.MEDIUM,
                    category=CAT_MACRO,
                    weight=0 if already_reported else 25,
                )
            )
        except Exception as exc:
            # Sink: any other library-level failure (the branch above covers
            # RecursionError specifically). The macro path produced no verdict,
            # so the same rule applies as there and as for the DDE/XLM stages:
            # a failure on a *readable* container is this stage's own news and
            # has to be weighted 25 — measured on a real macro document (real
            # MS-OVBA streams, AutoOpen + WScript.Shell) whose parser raised at
            # construction: score 0, verdict GREEN, the only indicator in the
            # whole scan was this weight-0 note. "Not analysed" must never look
            # like "clean". The one exception is the container itself: for an
            # unreadable one the dispatcher's MAIL_CONTAINER_WARN already
            # carries the 25 for the same cause (same bytes, same probe_outlook_msg
            # via _container_readable) — measured: a corrupt OLE container
            # scores exactly 25 once, not 50 ("eine Ursache, eine gewichtete
            # Aussage", the rule that also keeps OFFICE_VBA_STOP at 0 there).
            # The *silent* route of the same failure — the library catches it
            # itself and the export simply stays empty — never arrives here; it
            # is reported above (``if not macro_names``).
            already_reported = not _container_readable(ctx.data, ctx.detected_type)
            out.append(
                self._indicator(
                    "OFFICE_VBA_WARN",
                    "VBA-Analyse fehlerhaft — Makros NICHT ausgewertet",
                    detail=(
                        f"{type(exc).__name__}: {exc} — der Makro-Pfad wurde "
                        "nicht ausgewertet; das Ergebnis ist unvollständig und "
                        "nicht als 'sauber' zu werten."
                        + (
                            " Ursache ist derselbe nicht lesbare Container, den "
                            "der Scan bereits mit Gewicht 25 meldet; diese "
                            "Meldung bleibt deshalb die Diagnose (welche Stufe "
                            "es gemerkt hat)."
                            if already_reported
                            else ""
                        )
                    ),
                    severity=Severity.INFO if already_reported else Severity.MEDIUM,
                    category=CAT_MACRO,
                    weight=0 if already_reported else 25,
                )
            )
        return out

    def _vba_deep_indicators(
        self, combined_lower: str, reconstructed: list[str], has_autoexec: bool
    ) -> list[Indicator]:
        """Deobfuscation + behavioral heuristics over the full macro code.

        ``combined_lower`` is the lowercased raw macro code; ``reconstructed`` are
        the strings reassembled from literal/``Chr`` concatenation. Everything is
        static string analysis — no code is executed.
        """
        out: list[Indicator] = []
        recon_lower = " \n ".join(reconstructed).lower()

        # 1) Obfuscation: a suspicious marker reassembled that was NOT visible in
        #    the raw code (e.g. "pow" & "ershell" -> powershell).
        if recon_lower.strip():
            hidden = sorted(
                marker
                for marker in _OBFUSCATION_MARKERS
                if marker in recon_lower and marker not in combined_lower
            )
            if hidden:
                examples = " | ".join(s[:120] for s in reconstructed[:5])
                out.append(
                    self._indicator(
                        "OFFICE_VBA_OBFUSCATED",
                        "Verschleierte VBA-Inhalte rekonstruiert: " + ", ".join(hidden),
                        detail=(
                            "Schlüsselwörter waren durch Verkettung/Chr() verborgen "
                            "und wurden statisch rekonstruiert (nicht ausgeführt). "
                            "Beispiele: " + examples
                        ),
                        severity=Severity.CRITICAL if has_autoexec else Severity.HIGH,
                        category=CAT_SCRIPT,
                        weight=50 if has_autoexec else 30,
                    )
                )

        # 2) Behavioral patterns over raw + reconstructed text.
        haystack = combined_lower + "\n" + recon_lower
        for rule_id, label, severity, weight, groups in _VBA_BEHAVIOR_PATTERNS:
            matched: list[str] = []
            complete = True
            for group in groups:
                hit = next((kw for kw in group if kw in haystack), None)
                if hit is None:
                    complete = False
                    break
                matched.append(hit)
            if complete:
                out.append(
                    self._indicator(
                        rule_id,
                        f"{label}: " + ", ".join(matched),
                        detail="Verhaltensmuster im Makro-Code (rein statische Heuristik).",
                        severity=severity,
                        category=CAT_SCRIPT,
                        weight=weight,
                    )
                )
        return out

    def _vba_stomping_indicators(self, parser) -> list[Indicator]:
        """VBA-Stomping: der P-Code passt nicht zum sichtbaren Quelltext.

        Office führt bei einem Makro den kompilierten P-Code aus, nicht den
        Quelltext. Bei einem *gestompften* Dokument wurde der Quelltext
        ausgetauscht (oder ganz entfernt), während der P-Code die eigentliche
        Schadfunktion behält: jeder statische Makro-Scanner liest dann einen
        harmlosen oder leeren Text, Office führt trotzdem den P-Code aus.

        ``detect_vba_stomping()`` ist die passende oletools-API (vergleicht
        Schlüsselwörter aus dem mit ``pcodedmp`` disassemblierten P-Code mit dem
        Quelltext). Sie existiert in der geprüften Version (oletools 0.60.2,
        ``pcodedmp`` ist dort harte Abhängigkeit). Fehlt sie in einer älteren
        Installation, wird die Lücke NICHT selbst nachgebaut: ein eigener
        P-Code-Parser wäre ein zweiter, ungeprüfter Parser neben ``pcodedmp`` —
        die Lücke bleibt dann offen und ist genau hier dokumentiert.

        Ein Bibliotheksfehler (die Methode greift intern auf ``pcodedmp`` zu)
        darf die Makro-Stufe nicht sprengen: dann gibt es hier keinen Befund,
        die übrigen Makro-Meldungen bleiben aber stehen.
        """
        if not hasattr(parser, "detect_vba_stomping"):
            return []
        try:
            stomped = bool(parser.detect_vba_stomping())
        except Exception:
            return []
        if not stomped:
            return []
        return [
            self._indicator(
                "OFFICE_VBA_STOMPED",
                "Makro versteckt (P-Code passt nicht zum Quelltext)",
                detail=(
                    "Der im Dokument gespeicherte P-Code passt nicht zum "
                    "sichtbaren VBA-Quelltext (oder es gibt gar keinen). "
                    "Office führt den P-Code aus — eine Prüfung, die nur den "
                    "Quelltext liest, sieht deshalb ein harmloses Makro. Das "
                    "ist das Kennzeichen von VBA-Stomping; das Dokument wurde "
                    "sehr wahrscheinlich manipuliert."
                ),
                severity=Severity.HIGH,
                category=CAT_MACRO,
                weight=30,
            )
        ]

    # -- Stufe: externe Beziehungen & Metadaten (nur ctx.data) -------------- #

    def _ooxml_rels_analysis(self, ctx: AnalysisContext) -> list[Indicator]:
        """Externe Beziehungen eines OOXML-Containers (Remote Template Injection).

        Eine ``.docx``/``.xlsx`` kann beim Öffnen Inhalte von einem fremden
        Server nachladen — ohne jedes Makro. Die ``attachedTemplate``-Beziehung
        ist der gefährliche Fall (Word lädt die Vorlage samt Makros nach), die
        übrigen externen Beziehungen (``externalLink``, ``oleObject``, externe
        ``image``) sind ein Hinweis. Gelesen wird nur; nichts wird entpackt
        oder ausgeführt.
        """
        if not _ooxml_applicable(ctx.data):
            return []
        notes: list[str] = []
        try:
            relationships = external_relationships(ctx.data, notes=notes)
        except Exception:  # pragma: no cover - die Funktion fängt selbst ab
            return []
        out: list[Indicator] = []
        # Ein gekappter Mitglieder-Deckel ist eine Aussage über die VOLLSTÄNDIGKEIT
        # der Prüfung und muss sichtbar sein, auch wenn kein Fund dabei war.
        if notes:
            out.append(
                self._indicator(
                    "OFFICE_REL_TRUNCATED",
                    "Prüfung externer Beziehungen unvollständig",
                    detail=" ".join(notes),
                    severity=Severity.INFO,
                    category=CAT_SCRIPT,
                    weight=0,
                )
            )
        if not relationships:
            return out
        templates = [target for typ, target in relationships if typ == "attachedTemplate"]
        others = [(typ, target) for typ, target in relationships if typ != "attachedTemplate"]
        if templates:
            shown = " | ".join(target[:200] for target in templates[:8])
            out.append(
                self._indicator(
                    "OFFICE_REMOTE_TEMPLATE",
                    "Dokument lädt Inhalt aus dem Internet nach",
                    detail=(
                        "Das Dokument verweist auf eine externe Vorlage "
                        "(Remote Template Injection): " + shown + ". Beim "
                        "Öffnen lädt Office die Vorlage vom fremden Server und "
                        "kann deren Makros ausführen — die Datei selbst enthält "
                        "dabei kein Makro und wirkt auf den ersten Blick "
                        "harmlos."
                    ),
                    severity=Severity.HIGH,
                    category=CAT_SCRIPT,
                    weight=30,
                )
            )
        if others:
            shown = " | ".join(f"{typ}: {target[:200]}" for typ, target in others[:8])
            out.append(
                self._indicator(
                    "OFFICE_EXTERNAL_REL",
                    "Dokument verweist auf externe Inhalte",
                    detail=(
                        "Das Dokument lädt beim Öffnen Inhalte aus dem Internet "
                        "nach (ohne Makro): " + shown + ". Das kann eine "
                        "Fernladefunktion des Angreifers sein, kann aber auch "
                        "ein gewollter externer Datenbezug sein."
                    ),
                    # GEMESSEN zu hoch angesetzt: an einer echten .xlsx
                    # (Good-Samples) hob diese Regel eine sonst saubere Datei
                    # von 0 auf 20 und damit von GRUEN auf GELB — zusammen mit
                    # GEN_IOC (5). Ein online eingebundenes Bild ist in
                    # Geschaeftsdokumenten aber normal. Dieselbe Ueberkorrektur
                    # wie bei MAIL_AUTH_ABSENT und beim Zaehlpixel: was auf
                    # gewoehnlichen Dateien feuert, ist keine 15 wert. Die
                    # gefaehrliche Variante — eine nachgeladene VORLAGE — hat
                    # mit OFFICE_REMOTE_TEMPLATE eine eigene, hoehere Regel.
                    severity=Severity.LOW,
                    category=CAT_IOC,
                    weight=5,
                )
            )
        return out

    def _metadata_analysis(self, ctx: AnalysisContext) -> list[Indicator]:
        """Verfasser-Angaben aus dem Dokument — reine Information, Gewicht 0.

        Autor, Firma, „zuletzt gespeichert von", Erzeuger und Vorlage stammen
        entweder aus den ``docProps``-Mitgliedern des OOXML-Containers oder aus
        den OLE-Property-Sets von ``.doc``/``.xls``. Sie werden ausdrücklich
        NICHT bewertet: die Angaben sind frei wählbar. Für den Nutzer sind sie
        trotzdem nützlich — seriöse Absender tragen hier ihre Firma ein, ein
        angebliches Bank-Dokument mit einem Privatnutzer als Autor ist ein
        Hinweis, den ein Laie ohne Malaz nie zu sehen bekäme.
        """
        values: dict[str, str] = {}
        if zipfile.is_zipfile(io.BytesIO(ctx.data)):
            values = _ooxml_metadata(ctx.data)
        if not values:
            values = _ole_metadata(ctx.data)
        parts: list[str] = []
        for label, keys in _METADATA_KEYS:
            for key in keys:
                if key in values:
                    parts.append(f"{label}: {values[key][:_METADATA_MAX_VALUE_CHARS]}")
                    break
        if not parts:
            return []
        return [
            self._indicator(
                "OFFICE_METADATA",
                "Dokument-Metadaten (nur Information)",
                detail=(
                    "Im Dokument gespeicherte Verfasser-Angaben — frei wählbar "
                    "und daher kein Beweis, aber ein Hinweis. "
                    + " | ".join(parts)
                    + ". Seriöse Absender (etwa eine Bank) tragen hier "
                    "üblicherweise ihre Firma ein, nicht einen Privatnutzer."
                ),
                severity=Severity.INFO,
                category=CAT_METADATA,
                weight=0,
            )
        ]

    # -- stage 2: DDE ------------------------------------------------------ #

    def _dde_analysis(
        self, ctx: AnalysisContext, tmp: str, depth_frames: int | None = None
    ) -> list[Indicator]:
        try:
            from oletools import msodde
        except Exception:
            # Fehlende Bibliothek: eine Installationstatsache, der DATEI nicht
            # anzulasten — aber sichtbar. Vorher stand hier nur `return []`.
            return self._lib_fehlt("DDE-Verknuepfungen (msodde)", "oletools")

        try:
            # BUG-025: ohne Feld-Filter liefert msodde ALLE Word-Felder
            # (``FIELD_FILTER_ALL``) — ``PAGE``, ``MERGEFIELD``, ``TOC``. Jedes
            # Dokument mit Seitenzahlen oder Serienbrief wurde damit GELB 30
            # mit der falschen HIGH-Meldung "DDE". Der DDE-Filter liefert nur
            # Felder, deren Anweisung mit ``DDE``/``DDEAUTO`` beginnt; für OLE
            # filtert msodde bereits selbst (``process_doc``/``process_xls``).
            dde_links = msodde.process_file(
                tmp, field_filter_mode=msodde.FIELD_FILTER_DDE
            )
        except Exception as exc:
            # Runde 4: this failure used to be swallowed twice over — the inner
            # handler turned it into `dde_links = ""` (no indicator at all) and
            # the outer one carried weight 0. Measured: msodde raises
            # AssertionError on a readable OOXML whose member XML is truncated
            # (pre-fix: the scan stayed GREEN with *no* other indicator), and on
            # broken containers (ValueError/OSError). Not read is not "clean":
            # same class as OFFICE_VBA_STOP / OFFICE_FORMULA_STOP — unless the
            # cause is already weighted elsewhere: the unreadable container by
            # the dispatcher (see _container_readable), the too-deep directory
            # tree by OFFICE_VBA_STOP (same measurement, passed down from
            # analyze()). msodde walks the same tree through olefile, so its
            # failure is the same fact, not a second one.
            container_unreadable = not _container_readable(ctx.data, ctx.detected_type)
            depth_too_deep = _ole_directory_too_deep(depth_frames)
            already_reported = container_unreadable or depth_too_deep
            return [
                self._indicator(
                    "OFFICE_DDE_PARSE_WARN",
                    "DDE-Analyse fehlerhaft — DDE-Links NICHT geprüft",
                    detail=(
                        f"{type(exc).__name__}: {exc} — die DDE-Links konnten "
                        "nicht gelesen werden."
                        + (
                            " Ursache ist der nicht lesbare Container; diese "
                            "Tatsache trägt bereits die Container-Meldung des "
                            "Scans mit Gewicht 25, deshalb bleibt es hier bei "
                            "der Diagnose (welche Stufe es gemerkt hat)."
                            if container_unreadable
                            else (
                                " Ursache ist der Verzeichnisbaum, den olefile "
                                "nicht mehr durchläuft; dieselbe Tatsache trägt "
                                "bereits OFFICE_VBA_STOP mit Gewicht 25, deshalb "
                                "bleibt es hier bei der Diagnose (welche Stufe "
                                "es gemerkt hat)."
                                if depth_too_deep
                                else " Das Ergebnis ist unvollständig und nicht "
                                "als 'sauber' zu werten."
                            )
                        )
                    ),
                    severity=Severity.INFO if already_reported else Severity.MEDIUM,
                    category=CAT_SCRIPT,
                    weight=0 if already_reported else 25,
                )
            ]
        text = str(dde_links).strip()
        if not text:
            return []
        return [
            self._indicator(
                "OFFICE_DDE",
                "DDE-Datenlink gefunden",
                detail="DDE kann beim Öffnen externe Befehle ausführen. Inhalt: " + text[:512],
                severity=Severity.HIGH,
                category=CAT_SCRIPT,
                weight=30,
            )
        ]

    # -- stage 3: XLM emulation -------------------------------------------- #

    _XLM_TIMEOUT_SECONDS = 120

    def _xlm_analysis(
        self, ctx: AnalysisContext, tmp: str, depth_frames: int | None = None
    ) -> list[Indicator]:
        try:
            # Suppress the pywin32 warning at import time (the library's
            # silent flag only applies at runtime, the warning is printed
            # during module import on stdout).
            import XLMMacroDeobfuscator.configs.settings as _xlm_settings

            _xlm_settings.SILENT = True
            # process_file is the real API of current versions; the class
            # XLMDeobfuscator referenced here historically does not exist —
            # the stage never ran at all (found during coverage expansion).
            from XLMMacroDeobfuscator.deobfuscator import process_file
        except Exception as exc:
            log.warning(
                "XLM-Stufe nicht verfuegbar: %s: %s", type(exc).__name__, exc
            )
            return self._lib_fehlt(
                "Excel-4.0-Makros (XLM)",
                "XLMMacroDeobfuscator",
                detail=f"{type(exc).__name__}: {exc}",
            )

        out: list[Indicator] = []
        try:
            result_q: queue.Queue[tuple[str, list | Exception]] = queue.Queue()

            def _worker() -> None:
                try:
                    res = process_file(
                        file=tmp,
                        noninteractive=True,
                        silent=True,
                        return_deobfuscated=True,
                        timeout=self._XLM_TIMEOUT_SECONDS,
                        # day>0 skips guess_day(), which would otherwise
                        # run 31 FULL emulations with timeout=0 — a
                        # crafted DAY() macro could block the worker
                        # indefinitely (hunt finding A2).
                        day=1,
                        # The library would silently decrypt encrypted
                        # workbooks with the well-known malware default
                        # password "VelvetSweatshop" and LEAK the
                        # decrypted copy into %TEMP% forever. A password
                        # that never matches avoids both (hunt finding
                        # A3) — encrypted inputs degrade to a silent
                        # emulation error like any other.
                        password="malaz-no-default-pw",  # noqa: S106 - absichtlich nie passend
                    )
                    result_q.put(("ok", res))
                except Exception as exc:  # best-effort: no XLM is common
                    result_q.put(("error", exc))

            worker = threading.Thread(target=_worker, daemon=True)
            worker.start()
            worker.join(self._XLM_TIMEOUT_SECONDS)
            timed_out = worker.is_alive()
            if timed_out:
                # The library's own timeout is SOFT (it only stops
                # between cell evaluations; a single hanging evaluation
                # blocks forever) — the wall clock here is the only
                # reliable budget (hunt finding A1/A2).
                out.append(
                    self._indicator(
                        "OFFICE_XLM_TIMEOUT",
                        "XLM-Emulation abgebrochen (Zeitbudget)",
                        detail=(
                            f"Die Excel-4.0-Emulation lief länger als "
                            f"{self._XLM_TIMEOUT_SECONDS} s — mögliches "
                            "Verzögerungs-Konstrukt; XLM-Befunde sind "
                            "unvollständig."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_SCRIPT,
                        # 25, not 15: the wall-clock abort means the XLM stage
                        # delivered no verdict. Measured before this change: a
                        # workbook whose emulation ran into the budget scored
                        # 15 — below SCORE_GREEN_MAX (19), so an attacker's
                        # delay construct bought a GREEN verdict. The abort and
                        # the emulator error below are the same fact ("stage did
                        # not run") and must not be weighed differently.
                        weight=25,
                    )
                )
                # The still-running daemon may hold the temp file open —
                # deleting now would PermissionError and leak it forever.
                # A daemon timer retries after it had its chance.
                cleanup = threading.Timer(
                    self._XLM_TIMEOUT_SECONDS,
                    lambda p=tmp: _try_unlink(p),
                )
                cleanup.daemon = True
                cleanup.start()
                return out
            try:
                status, payload = result_q.get_nowait()
            except queue.Empty:  # pragma: no cover - defensive
                return out
            if status == "error":
                log.warning(
                    "XLM-Emulation fehlgeschlagen: %s: %s",
                    type(payload).__name__, payload,
                )
                # Runde 4: this branch used to `return out` with an empty list —
                # the stage produced no indicator at all, so a workbook whose
                # Excel-4.0 macros were never emulated was indistinguishable
                # from one without XLM macros. Same treatment (and same
                # container rule) as the DDE stage: the cause travels through
                # olefile, so an unreadable container (dispatcher's
                # MAIL_CONTAINER_WARN) or a directory tree beyond the walk
                # budget (OFFICE_VBA_STOP, measured once in analyze()) is
                # already weighted — this stays the diagnosis.
                fehler = payload
                container_unreadable = not _container_readable(ctx.data, ctx.detected_type)
                depth_too_deep = _ole_directory_too_deep(depth_frames)
                already_reported = container_unreadable or depth_too_deep
                applicable = _xlm_applicable(ctx.data)
                weighted = applicable and not already_reported
                return [
                    self._indicator(
                        "OFFICE_XLM_PARSE_WARN",
                        "XLM-Analyse fehlerhaft — Excel-4.0-Makros NICHT emuliert",
                        detail=(
                            f"{type(fehler).__name__}: {fehler} — die Excel-4.0-Makros "
                            "wurden nicht emuliert."
                            + (
                                " Ursache ist der nicht lesbare Container; diese "
                                "Tatsache trägt bereits die Container-Meldung des "
                                "Scans mit Gewicht 25, deshalb bleibt es hier bei "
                                "der Diagnose."
                                if container_unreadable
                                else (
                                    " Ursache ist der Verzeichnisbaum, den olefile "
                                    "nicht mehr durchläuft; dieselbe Tatsache trägt "
                                    "bereits OFFICE_VBA_STOP mit Gewicht 25, deshalb "
                                    "bleibt es hier bei der Diagnose."
                                    if depth_too_deep
                                    else (
                                        " Dieser Container enthält gar keine "
                                        "Arbeitsmappe (weder Workbook-/Book-"
                                        "Stream noch xl/workbook.xml|bin) — es "
                                        "gibt nichts zu emulieren, der Befund bleibt "
                                        "deshalb bei Gewicht 0."
                                        if not applicable
                                        else " Das Ergebnis ist unvollständig und "
                                        "nicht als 'sauber' zu werten."
                                    )
                                )
                            )
                        ),
                        severity=Severity.MEDIUM if weighted else Severity.INFO,
                        category=CAT_SCRIPT,
                        weight=25 if weighted else 0,
                    )
                ]
            cells = [str(r) for r in (payload if isinstance(payload, list) else [])]
            blob = " ".join(cells).lower()
            # Only unambiguous execution primitives: "goto"/"halt"
            # are ordinary cell text (German "halt"!) and produced
            # false CRITICAL anchors on benign sheets.
            if any(tok in blob for tok in ("ex" + "ec", "ca" + "ll(")):
                out.append(
                    self._indicator(
                        "OFFICE_XLM",
                        "XLM-Makro (Excel 4.0) mit EXEC/CALL emuliert",
                        detail="Verschleierte XLM-Befehle wurden in der Emulation sichtbar.",
                        severity=Severity.CRITICAL,
                        category=CAT_SCRIPT,
                        weight=50,
                    )
                )
        except Exception:
            # Safety net around the queue/collection work above (the emulator's
            # own failure is reported at its source): the same fact and the same
            # container rule — the stage did not deliver a verdict.
            already_reported = not _container_readable(ctx.data, ctx.detected_type)
            out.append(
                self._indicator(
                    "OFFICE_XLM_PARSE_WARN",
                    "XLM-Analyse fehlerhaft — Excel-4.0-Makros NICHT emuliert",
                    detail=(
                        f"{type(fehler).__name__}: {fehler} — die Excel-4.0-Makros "
                        "wurden nicht emuliert."
                        + (
                            " Ursache ist der nicht lesbare Container; diese "
                            "Tatsache trägt bereits die Container-Meldung des "
                            "Scans mit Gewicht 25, deshalb bleibt es hier bei "
                            "der Diagnose."
                            if already_reported
                            else " Das Ergebnis ist unvollständig und nicht als "
                            "'sauber' zu werten."
                        )
                    ),
                    severity=Severity.INFO if already_reported else Severity.MEDIUM,
                    category=CAT_SCRIPT,
                    weight=0 if already_reported else 25,
                )
            )
        return out

    # -- stage 4: formula analysis ----------------------------------------- #

    def _formula_analysis(self, ctx: AnalysisContext) -> list[Indicator]:
        try:
            import openpyxl
        except Exception:
            return self._lib_fehlt("Formel-Analyse (xlsx)", "openpyxl")

        out: list[Indicator] = []
        # Call-like signatures are assembled via concatenation so static
        # scanners do not mistake this detection table for actual calls.
        # =HYPERLINK() deliberately NOT listed: it is a standard formula in
        # ordinary price lists/catalogues and fired HIGH on every benign xlsx.
        dangerous = (
            "cm" + "d|", "powershell", "wscript",
            "ca" + "ll(", "ex" + "ec(", "file://",
        )
        # Cause: the declared sizes of the container decide the cost of
        # openpyxl's parse (sharedStrings is read in full before the first
        # cell), so the bomb rule is applied *before* the library sees the
        # bytes. The refusal is reported with weight: a stage that does not run
        # must not look like "no dangerous formula found".
        reason = _ooxml_bomb_guard(ctx.data)
        if reason is not None:
            return [
                self._indicator(
                    "OFFICE_FORMULA_STOP",
                    "Formelprüfung übersprungen (Bombenschutz)",
                    detail=(
                        f"{reason} Die Tabellenfunktionen wurden NICHT geprüft — "
                        "das Ergebnis ist unvollständig, nicht 'sauber'."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_SCRIPT,
                    weight=25,
                )
            ]
        # State of the parse lives outside the try: the results found before a
        # later failure must survive it (see below).
        hits: list[str] = []
        exhausted = False
        failure: Exception | None = None
        try:
            wb = openpyxl.load_workbook(io.BytesIO(ctx.data), read_only=True, data_only=False)
            try:
                # Cell budget: a crafted sheet dimension can pad iter_rows() to
                # billions of empty cells; stop once the budget is exhausted.
                seen_cells = 0
                for ws in wb.worksheets:
                    for row in ws.iter_rows():
                        for cell in row:
                            seen_cells += 1
                            if seen_cells > config.MAX_FORMULA_CELLS:
                                exhausted = True
                                break
                            value = cell.value
                            if isinstance(value, str) and value.startswith("="):
                                lowered = value.lower()
                                for token in dangerous:
                                    if token in lowered:
                                        hits.append(f"{ws.title}!{cell.coordinate}: {value[:80]}")
                                        break
                            if len(hits) >= 25:
                                break
                        if exhausted or len(hits) >= 25:
                            break
                    if exhausted or len(hits) >= 25:
                        break
            finally:
                wb.close()
        except Exception as exc:
            failure = exc
        # The findings are emitted AFTER the parse, never from inside the loop:
        # read_only=True parses the sheet XML lazily, so the row that makes
        # openpyxl raise is only reached while iterating. Before this, a hit
        # found in an earlier row disappeared with the exception — measured: an
        # xlsx whose A1 holds a real DDE formula (=cmd|"/C calc"!A0) and whose
        # later C3 carries an uncastable number scanned GREEN 0, with nothing
        # left but the weight-0 OFFICE_FORMULA_PARSE_WARN. A found payload must
        # not vanish because something behind it throws; the abort message
        # comes on top of it.
        if hits:
            out.append(
                self._indicator(
                    "OFFICE_FORMULA",
                    f"Gefährliche Tabellenfunktionen ({len(hits)})",
                    detail=" | ".join(hits),
                    severity=Severity.HIGH,
                    category=CAT_SCRIPT,
                    weight=30,
                )
            )
        if exhausted:
            # A truncated analysis must never look like "no dangerous
            # formula found": the budget stop is reported explicitly,
            # mirroring ARCH_MEMBER_STOP in the dispatcher. Without
            # this, a crafted sheet whose dimension pads iter_rows()
            # past the budget (measured: A1:XFD1048576 = 4 billion
            # cells) silently hides everything behind that point —
            # including real DDE formulas. MEDIUM/weight 25 keeps the
            # scan out of a green verdict while a genuine hit still
            # anchors at HIGH.
            out.append(
                self._indicator(
                    "OFFICE_FORMULA_STOP",
                    "Formelprüfung unvollständig (Zell-Limit)",
                    detail=(
                        f"Nach {config.MAX_FORMULA_CELLS} Zellen abgebrochen — "
                        "der Rest der Tabelle wurde NICHT auf gefährliche "
                        "Formeln geprüft. Ursache ist meist eine künstlich "
                        "aufgeblähte Tabellendimension. Das Ergebnis ist "
                        "unvollständig, nicht 'sauber'."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_SCRIPT,
                    weight=25,
                )
            )
        if failure is not None:
            # Same rule as the DDE/XLM stages: a stage that delivers no verdict
            # must not read as "no dangerous formula found". Measured: an xlsx
            # with a valid container, a clean sheet and one uncastable numeric
            # cell scored 0/GREEN with only this note — and one with a real DDE
            # formula in front of the bad cell scored 0/GREEN as well. Weighted
            # 25 like OFFICE_FORMULA_STOP and its siblings, with the two
            # established exceptions: a container the dispatcher already
            # reports as unreadable (ARCH_ZIP_ERROR carries the 25) and a
            # container that is no zip at all (mislabelled OLE — nothing that
            # could hold an OOXML workbook, see _ooxml_applicable).
            applicable = _ooxml_applicable(ctx.data)
            already_reported = not _container_readable(ctx.data, ctx.detected_type)
            weighted = applicable and not already_reported
            out.append(
                self._indicator(
                    "OFFICE_FORMULA_PARSE_WARN",
                    "Formel-Analyse fehlerhaft — Tabellenfunktionen NICHT geprüft",
                    detail=(
                        f"{type(failure).__name__}: {failure} — Tabellenfunktionen "
                        "konnten nicht vollständig geprüft werden."
                        + (
                            " Das Ergebnis ist unvollständig und nicht als "
                            "'sauber' zu werten."
                            if weighted
                            else (
                                " Dieser Container ist gar kein OOXML-Archiv "
                                "(kein lesbarer Zip) — es gibt keine "
                                "Arbeitsmappe zu prüfen, der Befund bleibt "
                                "deshalb bei Gewicht 0."
                                if not applicable
                                else " Ursache ist der nicht lesbare Container; "
                                "diese Tatsache trägt bereits die "
                                "Container-Meldung des Scans mit Gewicht 25, "
                                "deshalb bleibt es hier bei der Diagnose."
                            )
                        )
                    ),
                    severity=Severity.MEDIUM if weighted else Severity.INFO,
                    category=CAT_SCRIPT,
                    weight=25 if weighted else 0,
                )
            )
        return out
