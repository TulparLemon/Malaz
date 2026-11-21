"""PDF analysis pipeline (pikepdf-based).

Stages, each degrading gracefully when its library is unavailable:

1. Quick triage — count risk-prone PDF keywords on the raw bytes (pdfid-style,
   implemented internally so it always works, even on encrypted files).
2. Object / stream scan — incremental saves (``%%EOF``), object streams
   (``/ObjStm``), embedded files (pikepdf attachments API).
3. JavaScript scan — embedded ``/JS``/``/JavaScript`` actions are pulled out of
   the object graph structurally (including compressed streams and indirect
   references) and inspected statically.
4. Layout forensics — invisible text (text rendering mode ``3 Tr``) and a
   conservative color-on-color heuristic on the page content streams.

pikepdf (MPL-2.0) replaced PyMuPDF (AGPL). Under the project's
GPL-3.0-or-later both are compatible; the change was made for size and API,
not for licence reasons.

Encrypted PDFs are handled by :meth:`_open_pdf`. Decrypting a PDF is pure
cryptographic work over the byte streams (AES/RC4); it executes no JavaScript,
no Launch action and no embedded payload, so it is safe for static analysis and
cannot "break out" the way opening a document in a viewer can. Whether encrypted
files are opened at all is governed by ``config.PDF_TRY_DEFAULT_PASSWORDS``.
"""

from __future__ import annotations

import io
import re
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from .. import config
from ..core.binary_iocs import (
    BINARY_IOC_BLOCKED_TITLE,
    BLOCKLIST_UNAVAILABLE_TITLE,
    IOC_URL,
    host_of_url,
    is_namespace_host,
    split_blocked_iocs,
)
from ..core.js_deobf import deobfuscate_js
from ..core.risky_types import RISKY_SUFFIXES
from ..core.url_view import defang_url
from ..models import (
    CAT_IOC,
    CAT_SCRIPT,
    CAT_STEGO,
    CAT_STRUCTURE,
    AnalysisContext,
    Indicator,
    Severity,
)
from .base import Pipeline

# /AA as a DICTIONARY KEY only: the lookahead rejects longer names such as
# /AAPL:xx that macOS Quartz writes into every PDF — counting those as
# "Additional-Actions" produced false CRITICAL escalations of innocent JS.
_AA_KEY_RE = re.compile(rb"/AA(?![A-Za-z])")

# Upper bound for ONE decompressed stream (JS payload / content stream).
# pikepdf's read_bytes() materialises the FULL decompressed stream — a
# FlateDecode bomb (tiny file, gigabytes expanded) would otherwise OOM or
# freeze the worker with a single crafted PDF.
_MAX_STREAM_BYTES = 8 * 1024 * 1024


# Cumulative DECOMPRESSED budget for the layout stage. The per-stream cap
# above bounds ONE stream; it does not bound the sum over pages. GEMESSEN
# (PERF-002): a 12.7 KiB PDF whose pages all reference the same 4 MiB content
# stream produced a tracemalloc peak of 68/132/260 MiB with 8/16/32
# references — linear in the number of references, because every page kept its
# decompressed payload until it had been analysed. 40 references on a 6 KiB
# fixture already cost 40 MiB of live bytes for a 1.4 s stage. A crafted
# document must not be able to turn "look at the pages" into unbounded memory:
# once the budget is spent the stage stops and says so (PDF_PARSE_WARN),
# because "not looked at" is not "clean".
_MAX_LAYOUT_BYTES = 32 * 1024 * 1024


# Worst-case DECODE expansion per filter (output bytes per input byte).
# Flate/LZW reach ~1032:1 on degenerate all-repetitive input; RunLength
# decodes at most 64:1 (1 length byte + up to 128 data bytes per 2 input
# bytes); ASCIIHex and ASCII85 SHRINK on decode. Unknown filters (DCT,
# CCITT, JBIG2, custom) get the Flate-style worst case as a safe default —
# a crafted chain like [/FlateDecode /FlateDecode] multiplies to ~1e6:1
# and is therefore refused before anything is materialised.
_FILTER_EXPANSION: dict[str, float] = {
    "/FlateDecode": 1032,
    "/LZWDecode": 1032,
    "/RunLengthDecode": 64,
    "/ASCIIHexDecode": 0.5,
    "/ASCII85Decode": 0.8,
    "/Crypt": 1.0,
}
_UNKNOWN_EXPANSION = 1032


def _chain_expansion(names: list[str]) -> float:
    """Worst-case expansion factor of a filter chain (product of stages)."""
    factor = 1.0
    for name in names:
        factor *= _FILTER_EXPANSION.get(name, _UNKNOWN_EXPANSION)
    return factor


def _read_stream_bounded(stream, pikepdf) -> tuple[bytes | None, str | None]:
    """Read a decompressed stream with a hard output cap.

    Returns ``(payload, None)`` on success or ``(None, reason)`` when the
    stream is refused. FlateDecode(-only) streams are decompressed here with
    a bounded loop (the standard case for JS/content streams); any other
    filter chain is guarded by a raw-size x ratio estimate before pikepdf
    materialises it.
    """
    import zlib

    try:
        filters = stream.get(pikepdf.Name.Filter)
    except Exception:
        filters = None
    names: list[str] = []
    if filters is not None:
        names = (
            [str(f) for f in filters]
            if isinstance(filters, pikepdf.Array)
            else [str(filters)]
        )
    try:
        decode_parms = stream.get(pikepdf.Name.DecodeParms)
    except Exception:
        decode_parms = None

    if not names:
        # No filter: the raw bytes ARE the payload. Running them through
        # zlib would reject every unfiltered (hand-written / simple
        # generator) stream as "beschädigt" — regression caught in review.
        try:
            payload = stream.read_raw_bytes()
        except Exception as exc:
            return None, f"Stream nicht lesbar ({type(exc).__name__})"
        if len(payload) > _MAX_STREAM_BYTES:
            return None, (
                f"Stream > {_MAX_STREAM_BYTES} Bytes (Dekompressionsbombe-Verdacht)"
            )
        return payload, None

    if names == ["/FlateDecode"] and decode_parms is None:
        try:
            raw = stream.read_raw_bytes()
        except Exception as exc:
            return None, f"Stream nicht lesbar ({type(exc).__name__})"
        dec = zlib.decompressobj()
        out = bytearray()
        chunk_size = 1 << 20
        for pos in range(0, len(raw), chunk_size):
            try:
                out += dec.decompress(
                    raw[pos : pos + chunk_size], _MAX_STREAM_BYTES + 1 - len(out)
                )
            except zlib.error:
                return None, "Flate-Stream beschädigt"
            if len(out) > _MAX_STREAM_BYTES:
                return None, (
                    f"entpackter Stream > {_MAX_STREAM_BYTES} Bytes "
                    "(Dekompressionsbombe-Verdacht)"
                )
        try:
            out += dec.flush(_MAX_STREAM_BYTES + 1 - len(out))
        except zlib.error:
            return None, "Flate-Stream beschädigt"
        if len(out) > _MAX_STREAM_BYTES:
            return None, (
                f"entpackter Stream > {_MAX_STREAM_BYTES} Bytes "
                "(Dekompressionsbombe-Verdacht)"
            )
        if not dec.eof:
            if not raw:
                # Empty raw stream: some generators write empty content
                # streams WITH a filter — nothing is truncated, there is
                # simply no payload.
                return b"", None
            # The zlib stream never reached its end marker: the file is cut
            # off mid-stream. Return the readable prefix but flag it — the
            # analysis must not claim full coverage of a truncated payload.
            return bytes(out), "Flate-Stream unvollständig (abgeschnittene Datei)"
        return bytes(out), None

    # Everything else (exotic filters, Flate with /DecodeParms predictors,
    # filter chains): bound by a per-filter worst-case expansion estimate
    # BEFORE pikepdf materialises anything, then a hard check after.
    try:
        raw_len = len(stream.read_raw_bytes())
    except Exception as exc:
        return None, f"Stream nicht lesbar ({type(exc).__name__})"
    expansion = _chain_expansion(names)
    if decode_parms is not None:
        # PNG predictors add one filter byte per row; with 1-byte rows that
        # doubles the data — 6x is a comfortable safety margin. This
        # multiplier is deliberately conservative: LEGITIMATE streams
        # (Flate+Predictor images) can trip the estimate without being
        # bombs, so refusals caused by it report "unpruefbar", NOT bomb
        # suspicion (_warn_is_bomb must not match).
        expansion *= 6
        if raw_len * expansion > _MAX_STREAM_BYTES:
            return None, (
                f"Stream mit Predictor nicht prüfbar: geschätzte Expansion "
                f"{expansion:.0f}:1 übersteigt das Analyse-Limit"
            )
    elif raw_len * expansion > _MAX_STREAM_BYTES:
        # Pure filter-chain product (e.g. [/FlateDecode /FlateDecode] on
        # tiny raw bytes): no legitimate content trips this — treat as
        # bomb suspicion and refuse BEFORE pikepdf materialises anything.
        return None, (
            f"Stream-Filterkette überschreitet Größenlimit "
            f"(geschätzte Expansion {expansion:.0f}:1)"
        )
    try:
        payload = stream.read_bytes()
    except Exception as exc:
        return None, f"Stream nicht lesbar ({type(exc).__name__})"
    if len(payload) > _MAX_STREAM_BYTES:
        return None, f"entpackter Stream > {_MAX_STREAM_BYTES} Bytes"
    return payload, None



def _warn_is_bomb(reason: str) -> bool:
    """Classify a _read_stream_bounded refusal as bomb suspicion.

    Matches the actual bomb refusal strings ("Dekompressionsbombe-Verdacht",
    hard-limit messages, the pure filter-chain estimate). The Predictor
    estimate reports "nicht prüfbar" instead — a legitimate stream can trip
    that conservative multiplier without being a bomb, so it stays an
    ordinary INFO warning.
    """
    # Substring checks, not startswith: in the layout forensics the
    # reasons carry a "S. <n>: " prefix that would break any prefix match.
    return (
        "Bombe" in reason
        or "entpackter Stream >" in reason
        or "Stream > " in reason
        or "Größenlimit" in reason
    )

# keyword -> (severity, weight or None, title)
#
# DIE GEWICHTE SIND AN ECHTEN DATEIEN GEMESSEN, nicht geschaetzt. Gegenprobe:
# 13 echte Behoerdenformulare (IRS, VA, GSA, CMS — gemeinfrei) und 25 echte
# arXiv-Preprints. VORHER waren 12 von 13 Formularen ROT, und zwar an
# Merkmalen, die fuer Formulare voellig normal sind:
#
#   PDF_KW_EmbeddedFile(30)  Die IRS-Formulare haengen Arbeitsblaetter und
#                            Anleitungen als eingebettete Dateien an — genau
#                            das Merkmal feuerte auf JEDEM von ihnen.
#   PDF_KW_ObjStm(5) +       DASSELBE Merkmal zweimal gezaehlt: einmal als
#   PDF_OBJSTM(5)            Schluesselwort, einmal strukturell. Objekt-Streams
#                            sind seit PDF 1.5 (2003) der Standard, nicht eine
#                            Auffaelligkeit.
#   PDF_KW_AA(15)            Additional Actions: Formulare nutzen sie zur
#                            Feldvalidierung.
#
# Zum Vergleich das Referenzwerkzeug der PDF-Triage, pdfid.py (Didier
# Stevens): es ZAEHLT /JS, /OpenAction, /AA, /EmbeddedFile, /ObjStm und faellt
# KEIN Urteil — ausdruecklich, weil ein einzelnes /JS in einem grossen Teil
# legitimer PDFs steht. Dasselbe gilt hier: praesent heisst auffaellig, nicht
# gefaehrlich. Die Schwere kommt aus der Kombination (siehe _PDF_JS_MALICIOUS)
# und aus dem Auto-Start-Kontext.
_KEYWORD_RULES: dict[bytes, tuple[Severity, int | None, str]] = {
    # /JS und /JavaScript: praesent ist haeufig, aber nicht harmlos per se.
    # GEMESSEN und nachjustiert: mit Gewicht 0 wurde ein PDF, das JavaScript
    # enthaelt, ohne es automatisch zu starten, KOMPLETT GRUEN — eine echte
    # Verschlechterung (Testfixture js_no_autostart.pdf: YELLOW 30 -> GRUEN 0).
    # Mit 10 bleibt es GELB ("schau hin"), ohne dass ein Formular rot wird:
    # auf den 13 echten Behoerdenformularen und 25 arXiv-PDFs feuerte dieses
    # Schluesselwort gar nicht, weil das JS dort in Objekt-Streams liegt.
    b"/JavaScript": (Severity.LOW, 20, "JavaScript-Referenz (/JavaScript)"),
    b"/JS": (Severity.LOW, 20, "JavaScript-Aktion (/JS)"),
    # /Launch bleibt der Anker: ein Programmstart aus einem PDF hat keinen
    # legitimen Alltagsfall.
    b"/Launch": (Severity.CRITICAL, 50, "Launch-Aktion (/Launch) — Programmstart"),
    # /OpenAction nur zusammen mit einem BÖSARTIGEN JS-Primitiv (siehe dort),
    # fuer sich allein 15: eine Startaktion kann eine Seite oder ein Skript
    # aktivieren — beides gibt es legitim.
    b"/OpenAction": (Severity.MEDIUM, 15, "Automatische Aktion (/OpenAction)"),
    # /AA: Formulare nutzen es zur Validierung.
    b"/AA": (Severity.LOW, 5, "Additional-Actions (/AA)"),
    # /EmbeddedFile: das Schluesselwort ist der NAME EINES OBJEKTTYPS, kein
    # Beleg fuer einen Anhang. GEMESSEN: die 12 echten IRS/VA/GSA-Formulare
    # tragen es 8-11x im Rohbyte — die STRUKTURELLE Pruefung (die den echten
    # Anhangsbaum liest, PDF_EMBEDDED_FILES) findet dort aber KEINEN einzigen
    # Anhang. Das Schluesselwort zaehlt also eine Typbezeichnung, nicht eine
    # Datei.
    #
    # Gewicht 0, weil dieselbe Sache schon strukturell bewertet wird — und dort
    # richtig: PDF_EMBEDDED_FILES kennt die NAMEN der Anhaenge und feuert nur,
    # wenn wirklich eine Datei angehaengt ist. "Ein Artefakt, eine Wertung."
    b"/EmbeddedFile": (Severity.INFO, 0, "Eingebettete Datei (/EmbeddedFile)"),
    # Objekt-Streams: seit PDF 1.5 Standard. Der strukturelle Befund
    # (PDF_OBJSTM) beschreibt dasselbe und traegt die 5 — hier 0, sonst zaehlt
    # dasselbe Merkmal zweimal.
    b"/ObjStm": (Severity.INFO, 0, "Objekt-Stream (/ObjStm)"),
    b"/AcroForm": (Severity.INFO, 0, "Formular (/AcroForm)"),
    b"/XFA": (Severity.MEDIUM, 15, "XFA-Formular (/XFA)"),
    b"/RichMedia": (Severity.HIGH, 30, "RichMedia/Flash (/RichMedia)"),
    b"/SubmitForm": (Severity.MEDIUM, 15, "Formular-Submit (/SubmitForm)"),
    b"/Encrypt": (Severity.MEDIUM, 15, "Verschlüsselung (/Encrypt)"),
    b"/JBIG2Decode": (Severity.MEDIUM, 15, "JBIG2-Codec (/JBIG2Decode)"),
    b"/Page": (Severity.INFO, 0, "Seitenobjekte (/Page)"),
}

# Risk-prone / malicious JavaScript APIs in PDFs (lowercased substrings). These
# are the execution / exfiltration / known-exploit primitives, not the benign
# form-calculation helpers, to keep false positives low. Call-like signatures
# are assembled via concatenation so static scanners (AV heuristics included)
# do not mistake this detection table for actual API calls.
# GETRENNT nach "belegt boesartig" und "in Dokumenten ueblich". Die Trennung
# ist an echten Dateien gemessen, nicht geschaetzt: auf 13 echten
# Behoerdenformularen (IRS, VA, GSA, CMS) feuerte von der alten Liste
# AUSSCHLIESSLICH "launchurl" — app.launchURL oeffnet eine Adresse, und genau
# das tut ein Formular, das auf seine Anleitung verlinkt. Mit Auto-Start
# gekoppelt ergab das den Anker CRITICAL/50: ROT fuer ein IRS-Formular.
#
# Ein Anker darf nur aus einem Primitiv entstehen, das in einem harmlosen
# Dokument KEINEN Alltagsfall hat.
# Endungen, die in einem PDF-Anhang nichts zu suchen haben: ein Dokument, das
# eine ausfuehrbare Datei mitbringt, ist ein Dropper.
# Der gemeinsame Kern steht in core/risky_types.py — EINE Quelle. GEMESSEN:
# die zweite Liste hier war neben der in core/eml_analysis bereits
# auseinandergelaufen, und ".hwp" fehlte genau dieser Fassung.
#
# Die Zusatz-Endungen sind der UNTERSCHIED im Kontext, nicht Schlamperei:
# in einer MAIL ist eine .zip ein gewoehnlicher Anhang (er wird ohnehin
# entpackt und rekursiv geprueft — sie als "aktiven Anhangtyp" zu melden
# liesse jede Geschaeftsmail anschlagen, siehe
# test_benign_attachment_names_stay_clean). In einem PDF EINGEBETTET ist
# eine .zip ein Umgehungsversuch: sie wird nicht entpackt, und der Nutzer
# sieht sie nicht.
_EMBEDDED_ONLY_SUFFIXES = (".zip", ".rar", ".7z", ".apk", ".sh", ".py")
_EMBEDDED_DANGEROUS_SUFFIXES = RISKY_SUFFIXES + _EMBEDDED_ONLY_SUFFIXES


def _embedded_name_for_suffix(name: str) -> str:
    """Normalise an attachment name the way Windows resolves it on disk.

    GEMESSEN (BUG-018): ``payload.exe`` scored CRITICAL/50, but
    ``payload.exe `` / ``payload.exe.`` / ``payload.exe::$DATA`` only produced
    the harmless "embedded files" note — the suffix check asked the raw name.
    ``safe_extract`` already strips trailing dots/spaces per component and
    cuts at the NTFS alternate-data-stream separator, so exactly these names
    land as ``payload.exe`` there. The suffix question has to be the same one
    or the extension check is trivially bypassed.
    """
    # Both separators occur in the wild; the last component is the file name.
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    base = base.split(":", 1)[0]  # NTFS ADS: everything after ':' is a stream
    return base.rstrip(". ")


_ZAHL = rb"(?:\d+(?:\.\d*)?|\.\d+)"
# Fill-colour operators: ``g`` (1 operand), ``rg``/``sc``/``scn`` (1-4) and
# ``k`` (4, CMYK). Bounded to four operands so the pattern cannot scan a long
# run of numbers; the operator decides how many are actually valid.
_FARB_OP = re.compile(
    rb"(?<![\w.])("
    + _ZAHL
    + rb"(?:\s+"
    + _ZAHL
    + rb"){0,3})\s+(rg|sc|scn|g|k)\b"
)
_TEXT_OP = re.compile(
    rb"(?:\((?:[^()\\]|\\.)*\)\s*Tj|\[(?:[^\]\\]|\\.)*\]\s*TJ)"
)
# One token of a content stream. Strings, hex strings, arrays and comments are
# recognised as a WHOLE so their payload can never be mistaken for an operator:
# without this, a literal ``(0 0 0 rg)`` before a white ``Tj`` reset the colour
# state and hid exactly the invisible text this heuristic looks for.
_PDF_TOKEN = re.compile(
    rb"\((?:[^()\\]|\\.)*\)"
    rb"|<[0-9A-Fa-f\s]*>"
    rb"|\[(?:[^\[\]\\]|\\.)*\]"
    rb"|%[^\r\n]*"
    rb"|\S+"
)


def _farbe_ist_weiss(operator: bytes, werte: list[float]) -> bool:
    """Does this fill-colour operator paint WHITE?

    ``g``/``rg`` are additive (1.0 = full), ``k`` (CMYK) is subtractive
    (0/0/0/0 = white paper). ``sc``/``scn`` depend on the current colour
    space; the operand count is the only local hint, so 1 = Gray, 3 = RGB,
    4 = CMYK. A malformed operand count is never white: an operator we cannot
    read must not preserve an older white state.
    """
    if operator == b"g":
        return len(werte) == 1 and werte[0] >= 0.999
    if operator == b"rg":
        return len(werte) == 3 and all(w >= 0.999 for w in werte)
    if operator == b"k":
        return len(werte) == 4 and all(w <= 0.001 for w in werte)
    if operator in (b"sc", b"scn"):
        if len(werte) == 1:
            return werte[0] >= 0.999
        if len(werte) == 3:
            return all(w >= 0.999 for w in werte)
        if len(werte) == 4:
            return all(w <= 0.001 for w in werte)
    return False


def _hat_weissen_text(inhalt: bytes) -> bool:
    """Wird Text MIT weisser Fuellung gezeichnet — also unsichtbar?

    Die richtige Frage ist nicht "kommt Weiss irgendwo vor und Text irgendwo
    auch" (das trifft jedes Formular mit weissem Eingabefeld), sondern: ist
    der LETZTE Farboperator vor einem Textoperator weiss?

    Die erste Fassung dieser Verschaerfung verlangte, dass zwischen Fuellung
    und Text KEIN Buchstabe steht — und brach damit den echten Fall: in einem
    Inhaltstrom steht dort immer ``BT /F1 12 Tf``. Gemessen am Fixture
    color_on_color.pdf (``1 1 1 rg BT /F1 12 Tf (geheim) Tj ET``), das die
    Regel danach nicht mehr ausloeste. Der Rahmen ist deshalb nicht "keine
    Buchstaben", sondern "kein weiterer Farboperator dazwischen".

    BUG-022: the old operator table only matched values starting with ``1``,
    so ``0 0 0 rg`` / ``0 g`` / ``0 0 0 0 k`` never RESET the white state —
    white text after a reset stayed "white" (false positive), and a later
    black-only stream inherited the old white flag. Every fill-colour
    operator now updates the state, including the black/CMYK-white ones.
    """
    letzte_farbe_weiss = False
    pos = 0
    while pos < len(inhalt):
        treffer = _PDF_TOKEN.search(inhalt, pos)
        if treffer is None:
            break
        start = treffer.start()
        # Text operators start with a string/array token; check them BEFORE
        # the payload skip, or a literal ``(geheim) Tj`` would never be seen.
        if letzte_farbe_weiss and _TEXT_OP.match(inhalt, start):
            return True
        token = treffer.group()
        if token[:1] == b"%":
            pos = treffer.end()
            continue
        farbe = _FARB_OP.match(inhalt, start)
        if farbe is not None:
            werte = [float(w) for w in farbe.group(1).split()]
            letzte_farbe_weiss = _farbe_ist_weiss(farbe.group(2), werte)
            # Consume the whole operator: matching again at its second
            # operand would read a truncated (and thus black) sequence.
            pos = farbe.end()
            continue
        pos = treffer.end()
    return False


_PDF_JS_MALICIOUS = (
    "ev" + "al(",           # eval — Code aus Daten
    "app.ev" + "al",        # app.eval
    "exportdataobject",     # eingebettete Datei auf die Platte schreiben
    "collab.geticon",       # bekanntes Exploit-Primitiv
    "mail" + "msg(",        # Mail versenden
    "execdialog",           # Menuebefehl ausfuehren
)

# In Dokumenten ueblich. Bleibt als Befund sichtbar (Gewicht 10 statt 30),
# traegt aber KEINEN Anker.
_PDF_JS_COMMON = (
    "launchurl",            # Link oeffnen — jedes Formular mit Anleitung
    "submitform",           # Formular absenden
    "getannotation",        # Anmerkungen lesen
    "util.stringfromstream",
    "exportasstring",
)

# Obfuscation techniques used to hide a JS payload from keyword scanners.
_PDF_JS_OBFUSCATION = (
    "string.fromcharcode",
    "fromcharcode",
    "unescape(",
    "charcodeat",
    "\\u00",  # \u00xx unicode escape runs
    "\\x",    # \xXX hex escape runs
)


_OBF_CACHE: dict[bytes, re.Pattern] = {}


def _count_obfuscated_names(data: bytes, keyword: bytes) -> int:
    """Count occurrences of ``keyword`` tolerating #xx hex escapes.

    PDF name objects may encode any character as ``#xx`` (e.g.
    ``/J#61vaScript`` for ``/JavaScript``). For each keyword character the
    pattern accepts either the literal byte or the escape that DECODES to that
    byte, so obfuscated names match while plain occurrences are counted as well
    (callers subtract the plain count).

    The escape must be the character's own code: the first implementation
    accepted any ``#xx`` hex pair, so ``/J#00vaScript`` counted as
    ``/JavaScript`` although ``#00`` is NUL (BUG-021). Hex digits stay
    case-insensitive (``#61`` == ``#6A`` style), as the PDF spec requires.
    """
    pattern = _OBF_CACHE.get(keyword)
    if pattern is None:
        parts = []
        for byte in keyword:
            escape = b"#"
            for nibble in f"{byte:02x}":
                if nibble.isdigit():
                    escape += nibble.encode()
                else:
                    escape += f"[{nibble}{nibble.upper()}]".encode()
            parts.append(b"(?:" + re.escape(bytes([byte])) + b"|" + escape + b")")
        pattern = re.compile(b"".join(parts))
        # The cache is bounded by the fixed keyword table.
        _OBF_CACHE[keyword] = pattern
    return sum(1 for _ in pattern.finditer(data))


@dataclass
class _GraphWalk:
    """Structured result of :meth:`PdfPipeline._walk_action_graph`."""

    js_values: list = field(default_factory=list)
    uri_values: list = field(default_factory=list)
    launch_hits: int = 0
    truncated: bool = False
    visited: set[tuple[int, int]] = field(default_factory=set)
    incomplete: bool = False


# C-speed translation table stripping C0 controls (0x00..0x1F) and DEL (0x7F).
_C0_STRIP_TABLE = str.maketrans("", "", "".join(chr(c) for c in range(0x20)) + "\x7f")


def _decode_pdf_uri(raw: Any) -> str | None:
    """Decode a PDF ``/URI`` string safely (UTF-16BE/LE with or without BOM).

    Only accepts ``str``, ``bytes``, ``bytearray``, or ``pikepdf.String`` —
    never coerces PDF integers (``bytes(500_000_000)`` OOM DoS) or arrays.
    Caps raw input BEFORE decoding/scanning to bound memory and CPU.
    """
    max_chars = config.MAX_STRING_CAPTURE
    max_raw_bytes = max_chars * 4  # generous bound for UTF-16 + BOM + stripped C0s

    if isinstance(raw, str):
        decoded = raw[:max_raw_bytes]
    elif isinstance(raw, (bytes, bytearray)):
        raw_bytes = bytes(raw[:max_raw_bytes])
        decoded = ""
    else:
        try:
            import pikepdf

            if not isinstance(raw, pikepdf.String):
                return None
            raw_bytes = bytes(raw)[:max_raw_bytes]
            decoded = ""
        except Exception:
            return None

    if not isinstance(raw, str):
        if not raw_bytes:
            return None
        if raw_bytes.startswith(b"\xfe\xff"):
            body = raw_bytes[2:]
            if len(body) % 2:
                body = body[:-1]
            decoded = body.decode("utf-16-be", errors="replace")
        elif raw_bytes.startswith(b"\xff\xfe"):
            body = raw_bytes[2:]
            if len(body) % 2:
                body = body[:-1]
            decoded = body.decode("utf-16-le", errors="replace")
        elif len(raw_bytes) >= 4:
            even_len = len(raw_bytes) - (len(raw_bytes) % 2)
            sample = raw_bytes[:even_len]
            half = even_len // 2
            even_nul = sample[0::2].count(0) / half
            odd_nul = sample[1::2].count(0) / half
            if even_nul > 0.40 and odd_nul < 0.05:
                decoded = sample.decode("utf-16-be", errors="replace")
            elif odd_nul > 0.40 and even_nul < 0.05:
                decoded = sample.decode("utf-16-le", errors="replace")
            else:
                decoded = raw_bytes.decode("latin-1")
        else:
            decoded = raw_bytes.decode("latin-1")

    cleaned = decoded.translate(_C0_STRIP_TABLE).strip()
    if not cleaned:
        return None
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars]
    return cleaned


class PdfPipeline(Pipeline):
    name = "pdf"

    def analyze(self, ctx: AnalysisContext) -> list[Indicator]:
        indicators: list[Indicator] = []

        # Stage 1 works on raw bytes and therefore also runs on encrypted PDFs.
        indicators.extend(self._keyword_triage(ctx))

        pdf, enc_indicator = self._open_pdf(ctx)
        if enc_indicator is not None:
            indicators.append(enc_indicator)

        try:
            if pdf is not None:
                indicators.extend(self._structure_scan(ctx, pdf))
                indicators.extend(self._javascript_scan(ctx, pdf))
                indicators.extend(self._layout_forensics(ctx, pdf))
        finally:
            if pdf is not None:
                with suppress(Exception):
                    pdf.close()
        return indicators

    # -- opening / decryption --------------------------------------------- #

    def _open_pdf(self, ctx: AnalysisContext):
        """Open the PDF and, if encrypted, optionally decrypt it.

        Returns ``(pdf, indicator)`` where ``pdf`` is an open pikepdf document
        (or ``None`` when the library is missing, the file is unreadable, or an
        encrypted file is left closed) and ``indicator`` describes the
        encryption outcome (or the missing-library note).
        """
        if not config.has_capability("pikepdf"):
            return None, self._indicator(
                "PDF_LIB_MISSING",
                "pikepdf nicht verfügbar — Tiefen-Scan nicht gelaufen",
                detail=(
                    "Ohne pikepdf laufen die Stufen 2-4 (Objekte, JavaScript, "
                    "Layout) in dieser Installation überhaupt nicht; geprüft "
                    "wurden nur die Rohbytes. Das Ergebnis ist NICHT als "
                    "'sauber' zu werten."
                ),
                severity=Severity.MEDIUM,
                category=CAT_STRUCTURE,
                # 25, not 0: SCORE_GREEN_MAX is 19, so weight 0 presented a
                # file whose deep stages NEVER ran as GREEN — the same
                # false all-clear the CORE_ERROR fix removed from the
                # dispatcher. A stage that did not run is YELLOW, never green.
                weight=25,
            )

        import pikepdf

        # A large PDF is only present as a prefix; pikepdf can open the real
        # path and read the xref/objects lazily. Small files keep the
        # in-memory source (same behaviour, no extra file handle).
        pdf_source = (
            ctx.path
            if getattr(ctx, "source", None) is not None and ctx.size > len(ctx.data)
            else io.BytesIO(ctx.data)
        )

        try:
            pdf = pikepdf.open(pdf_source)
        except pikepdf.PasswordError:
            # A user password is required.
            if not config.PDF_TRY_DEFAULT_PASSWORDS:
                return None, self._indicator(
                    "PDF_ENCRYPTED",
                    "PDF verschlüsselt — Analyse abgebrochen (Schalter aus)",
                    detail=(
                        "Das PDF ist verschlüsselt und config.PDF_TRY_DEFAULT_PASSWORDS ist "
                        "deaktiviert. Die Roh-Bytes wurden trotzdem auf Keywords geprüft; "
                        "die Tiefen-Stufen 2-4 liefen NICHT."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_STRUCTURE,
                    # 25, not 15: 15 < SCORE_GREEN_MAX (19) classified an
                    # encrypted, unreadable PDF as GREEN. Encrypting a payload
                    # with a password is a one-line evasion of every deep
                    # stage; "content not inspected" is YELLOW, never green.
                    weight=25,
                )
            pdf = None
            for password in config.PDF_PASSWORDS:
                try:
                    pdf = pikepdf.open(pdf_source, password=password)
                    break
                except pikepdf.PasswordError:
                    continue
                except Exception as exc:
                    # Strukturfehler (kein Passwort-Problem): weiteres
                    # Passwort-Raten ist sinnlos. Ein raise hier würde die
                    # eigenen except-Klauseln umgehen (Geschwister-Handler
                    # fangen nicht) und den äußeren try/finally in analyze()
                    # sprengen — alle Tiefen-Ergebnisse wären verloren.
                    # Stattdessen sauber als WARN quittieren.
                    return None, self._indicator(
                        "PDF_PARSE_WARN",
                        "PDF konnte nicht geöffnet werden — Tiefen-Scan nicht gelaufen",
                        detail=(
                            f"{type(exc).__name__}: {exc} — die Stufen 2-4 "
                            "(Objekte, JavaScript, Layout) liefen NICHT; das "
                            "Ergebnis ist nicht als 'sauber' zu werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_STRUCTURE,
                        # 25, not 0: see PDF_LIB_MISSING above.
                        weight=25,
                    )
            if pdf is None:
                return None, self._indicator(
                    "PDF_ENCRYPTED",
                    "PDF verschlüsselt — kein Standardpasswort passte",
                    detail=(
                        "Das PDF ist verschlüsselt und keines der konfigurierten Passwörter "
                        "(config.PDF_PASSWORDS) passte. Die Roh-Bytes wurden trotzdem auf "
                        "Keywords geprüft; die Tiefen-Stufen 2-4 liefen NICHT. Das Ergebnis "
                        "ist nicht als 'sauber' zu werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_STRUCTURE,
                    # 25, not 15: 15 < SCORE_GREEN_MAX (19) = GREEN for a file
                    # we could not read at all. Same reasoning as the
                    # switch-off branch above.
                    weight=25,
                )
            return pdf, self._indicator(
                "PDF_ENCRYPTED_OPENED",
                "PDF verschlüsselt — mit Standardpasswort geöffnet",
                detail=(
                    "Das PDF war verschlüsselt und wurde zur statischen Analyse mit "
                    "einem konfigurierten Passwort entschlüsselt. Dabei wird kein "
                    "Code ausgeführt; lediglich der Inhalt wird sichtbar."
                ),
                severity=Severity.INFO,
                category=CAT_STRUCTURE,
                weight=0,
            )
        except Exception as exc:
            return None, self._indicator(
                "PDF_PARSE_WARN",
                "PDF konnte nicht geöffnet werden — Tiefen-Scan nicht gelaufen",
                detail=(
                    f"{type(exc).__name__}: {exc} — die Stufen 2-4 (Objekte, "
                    "JavaScript, Layout) liefen NICHT; das Ergebnis ist nicht "
                    "als 'sauber' zu werten."
                ),
                severity=Severity.MEDIUM,
                category=CAT_STRUCTURE,
                # 25, not 0: the measured case. A one-byte change in the xref
                # stream (/Size 8 -> /Size 9) made qpdf refuse a 726-byte PDF
                # whose payload (JS in an /ObjStm) only the deep stages see.
                # Weight 0 scored that file GREEN 5 while pypdf still read the
                # live /OpenAction JavaScript — an all-clear for an unread
                # file. Same lower bound as CORE_ERROR (dispatcher.py).
                weight=25,
            )

        if getattr(pdf, "is_encrypted", False):
            # Encrypted, but openable without a user password (owner-password-only
            # PDFs — the empty user password is implicit here).
            return pdf, self._indicator(
                "PDF_ENCRYPTED_OPENED",
                "PDF verschlüsselt — ohne Nutzerpasswort geöffnet",
                detail=(
                    "Das PDF ist (owner-)verschlüsselt, ließ sich aber ohne "
                    "Nutzerpasswort öffnen. Die Analyse ist rein statisch."
                ),
                severity=Severity.INFO,
                category=CAT_STRUCTURE,
                weight=0,
            )
        return pdf, None

    # -- stage 1: keyword triage ------------------------------------------- #

    def _keyword_triage(self, ctx: AnalysisContext) -> list[Indicator]:
        data = ctx.data
        out: list[Indicator] = []
        for keyword, (severity, weight, title) in _KEYWORD_RULES.items():
            # /AA counts KEY-ONLY: /AAPL:… (macOS Quartz) is NOT an
            # Additional-Actions key and must not count.
            count = (
                len(_AA_KEY_RE.findall(data))
                if keyword == b"/AA"
                else data.count(keyword)
            )
            if count:
                out.append(
                    self._indicator(
                        f"PDF_KW_{keyword.decode().strip('/')}",
                        f"{title} x{count}",
                        detail=f"Schlüsselwort {keyword.decode()} wurde {count}× im PDF gefunden.",
                        severity=severity,
                        category=CAT_SCRIPT if severity >= Severity.HIGH else CAT_STRUCTURE,
                        weight=weight,
                    )
                )

        # pdfid-style obfuscation counting: PDF names can be hex-escaped
        # (#xx), so "/J#61vaScript" is /JavaScript. A plain byte count misses
        # exactly the names a naive keyword scanner is meant to catch. Only
        # runs when the file contains a "#" at all (cheap prefilter).
        if b"#" in data:
            for keyword in _KEYWORD_RULES:
                obfuscated = _count_obfuscated_names(data, keyword) - data.count(keyword)
                if obfuscated > 0:
                    base_severity, base_weight, title = _KEYWORD_RULES[keyword]
                    if base_weight:
                        # Risky keyword: obfuscation never rates BELOW the
                        # plain-keyword baseline. Gated on the WEIGHT, not on
                        # the severity: /JS is LOW/20, so the old severity
                        # gate gave the hex-escaped name weight 5 while the
                        # readable one cost 20 — hiding the keyword made the
                        # file cheaper (BUG-020, measured 40 -> 10).
                        severity = base_severity
                        weight = base_weight
                    else:
                        # Harmless keyword (e.g. hex-escaped /Page is legal PDF
                        # practice): signal the odd escaping without letting a
                        # pile of them inflate the score to flat 15s.
                        severity = Severity.LOW
                        weight = 5
                    out.append(
                        self._indicator(
                            f"PDF_KW_{keyword.decode().strip('/')}_OBF",
                            f"{title} — obfuskiert x{obfuscated}",
                            detail=(
                                f"Das Schlüsselwort {keyword.decode()} kommt "
                                f"{obfuscated}× in #xx-hex-verschleierter Form vor "
                                "(z. B. /J#61vaScript)."
                            ),
                            severity=severity,
                            category=CAT_STRUCTURE,
                            weight=weight,
                        )
                    )
        return out

    # -- stage 2: structure / stream scan ---------------------------------- #

    def _structure_scan(self, ctx: AnalysisContext, pdf) -> list[Indicator]:
        import pikepdf

        out: list[Indicator] = []
        data = ctx.data

        # Incremental saves: more than one %%EOF marker indicates the document
        # was modified after initial save — a common exploit/cloaking technique.
        eof_count = data.count(b"%%EOF")
        if eof_count > 1:
            out.append(
                self._indicator(
                    "PDF_INCREMENTAL",
                    f"Inkrementelle Speicherung ({eof_count}× %%EOF)",
                    detail=(
                        "Mehrere %%EOF-Marker deuten auf nachträgliche Änderungen hin; "
                        "Inhalte können in späteren Revisionen versteckt sein."
                    ),
                    severity=Severity.LOW,
                    category=CAT_STRUCTURE,
                    weight=5,
                )
            )

        try:
            # Object streams: dictionaries with /Type /ObjStm can hide objects
            # from naive triage.
            objstm_seen = False
            for obj in pdf.objects:
                if obj is None:
                    continue
                try:
                    if obj.get(pikepdf.Name.Type) == pikepdf.Name("/ObjStm"):
                        objstm_seen = True
                        break
                except Exception:
                    continue
            if objstm_seen:
                out.append(
                    self._indicator(
                        "PDF_OBJSTM",
                        "Objekt-Streams (/ObjStm) vorhanden",
                        detail=(
                            "Objekt-Streams können Objekte vor einfacher Triage "
                            "verbergen — sie sind aber seit PDF 1.5 (2003) der "
                            "Standard und praktisch in jedem modernen PDF. "
                            "Deshalb kein Gewicht: der Befund bleibt sichtbar, "
                            "zaehlt aber nicht zum Urteil. GEMESSEN: er feuerte "
                            "auf 13 von 13 echten Behoerdenformularen und auf "
                            "dem groessten Teil der echten arXiv-Preprints."
                        ),
                        severity=Severity.INFO,
                        category=CAT_STRUCTURE,
                        weight=0,
                    )
                )

            # Embedded files via the standard /Names -> /EmbeddedFiles tree.
            try:
                names = list(pdf.attachments.keys())
            except Exception:
                names = []
            if names:
                # NICHT die Anwesenheit zaehlt, sondern WAS eingebettet ist.
                # GEMESSEN: die Fixture embedded_file.pdf bettet "anhang.txt"
                # ein — eine Textdatei, und sie war damit ROT 60. Ein PDF mit
                # einem eingebetteten Arbeitsblatt ist aber kein Angriff; die
                # IRS-Formulare liefern genau so ihre Anleitungen mit. Der
                # echte Dropper-Fall ist eine eingebettete AUSFUEHRBARE Datei.
                #
                # Deshalb stuft die Endung: gefaehrliche Typen behalten den
                # Anker, Dokumente bleiben ein Hinweis zum Nachsehen.
                namen = [str(n) for n in names]
                # BUG-018: the raw name is not what Windows writes to disk —
                # normalise (trailing dots/spaces, NTFS ADS) before asking for
                # the suffix, otherwise "payload.exe " is filed as harmless.
                gefaehrlich = [
                    n for n in namen
                    if PurePosixPath(_embedded_name_for_suffix(n)).suffix.lower()
                    in _EMBEDDED_DANGEROUS_SUFFIXES
                ]
                if gefaehrlich:
                    out.append(
                        self._indicator(
                            "PDF_EMBEDDED_EXECUTABLE",
                            f"Eingebettete ausführbare Datei ({len(gefaehrlich)})",
                            detail=(
                                "Ein PDF, das eine ausführbare Datei mitbringt, ist "
                                "der klassische Dropper: das Dokument oeffnet sich "
                                "harmlos, die Nutzlast liegt bei. Namen: "
                                + ", ".join(gefaehrlich[:10])
                            ),
                            severity=Severity.CRITICAL,
                            category=CAT_STRUCTURE,
                            weight=50,
                        )
                    )
                else:
                    out.append(
                        self._indicator(
                            "PDF_EMBEDDED_FILES",
                            f"Eingebettete Dateien ({len(namen)})",
                            detail=(
                                "Keine ausfuehrbaren Typen darunter. Namen: "
                                + ", ".join(namen[:10])
                            ),
                            severity=Severity.LOW,
                            category=CAT_STRUCTURE,
                            # 20 = GELB: ein PDF, das eine Datei mitbringt, soll
                            # angesehen werden — auch wenn sie harmlos ist.
                            weight=20,
                        )
                    )

            # SEC-013: /Launch structurally, not just as a raw byte count.
            # An action dictionary inside an /ObjStm is Flate-compressed and
            # therefore invisible to _keyword_triage; a DIRECT action dict
            # (``/OpenAction << /S /Launch /F (cmd.exe) >>``) never appears in
            # ``pdf.objects`` either, so the old keyword counter was the only
            # line of defence and both variants scored GREEN.
            #
            # The rule id is deliberately PDF_KW_Launch: scoring keeps the
            # HIGHEST value per rule id, so an action that the raw bytes also
            # contain is still counted exactly once.
            walk = self._walk_action_graph(pdf, collect_js=False, collect_uris=True)
            launch_hits = walk.launch_hits
            graph_truncated = walk.truncated
            if launch_hits:
                out.append(
                    self._indicator(
                        "PDF_KW_Launch",
                        f"Launch-Aktion (/Launch) — Programmstart x{launch_hits}",
                        detail=(
                            f"Im Objektgraph wurde {launch_hits}× eine "
                            "Launch-Aktion gefunden (/S /Launch bzw. Schlüssel "
                            "/Launch). Ein PDF, das ein Programm startet, hat "
                            "keinen legitimen Alltagsfall; in einem "
                            "Objekt-Stream sieht die Rohbyte-Prüfung die "
                            "komprimierte Aktion nicht."
                        ),
                        severity=Severity.CRITICAL,
                        category=CAT_SCRIPT,
                        weight=50,
                    )
                )
            if graph_truncated:
                # One warning for the fact "the action graph was not fully
                # walked" — the JavaScript stage shares this bound, so it does
                # not repeat the same note (rule ids would otherwise sum).
                out.append(
                    self._indicator(
                        "PDF_PARSE_WARN",
                        "PDF-Struktur-Scan unvollständig — Aktionsgraph zu tief/groß",
                        detail=(
                            "Der Objektgraph überschritt die Grenze von "
                            f"{self._GRAPH_MAX_NODES} Objekten bzw. "
                            f"{self._GRAPH_MAX_DEPTH} Ebenen; Launch-Aktionen "
                            "und JavaScript dahinter wurden NICHT vollständig "
                            "geprüft. Das Ergebnis ist nicht als 'sauber' zu "
                            "werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_STRUCTURE,
                        # 20, not 25: this warning says the graph walk hit its
                        # bound, not that the file could not be opened. On a
                        # real VA form (21-526ez) it combined with /JS (20),
                        # launchURL (10) and incremental saves (5) to RED 60;
                        # 20 keeps "unvollständig" YELLOW on its own without
                        # turning common form JavaScript into a block verdict.
                        weight=20,
                    )
                )
            if walk.incomplete:
                out.append(
                    self._indicator(
                        "PDF_PARSE_WARN",
                        "PDF-Struktur-Scan unvollständig — Seitenbaum/Root nicht lesbar",
                        detail=(
                            "Weder Seitenbaum noch Dokument-Root ließen sich "
                            "durchlaufen; Links (/URI) und Aktionen wurden NICHT "
                            "geprüft. Das Ergebnis ist nicht als 'sauber' zu werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_STRUCTURE,
                        weight=20,
                    )
                )
            if walk.uri_values:
                out.extend(self._link_indicators(walk.uri_values))
        except Exception as exc:
            out.append(
                self._indicator(
                    "PDF_PARSE_WARN",
                    "PDF-Struktur-Scan fehlerhaft — Objekt-/Anhang-Scan unvollständig",
                    detail=(
                        f"{type(exc).__name__}: {exc} — /ObjStm und eingebettete "
                        "Dateien wurden NICHT vollständig ausgewertet; das "
                        "Ergebnis ist nicht als 'sauber' zu werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_STRUCTURE,
                    # 25, not 0: a partially evaluated structure is not a clean
                    # file (see PDF_PARSE_WARN in _open_pdf).
                    weight=25,
                )
            )
        return out

    # -- stage 2b: embedded JavaScript ------------------------------------- #

    def _javascript_scan(self, ctx: AnalysisContext, pdf) -> list[Indicator]:
        """Extract embedded JavaScript and analyse it for abuse / obfuscation.

        The keyword triage (stage 1) only counts ``/JavaScript``/``/JS`` markers
        on the raw bytes; here the actual script code is pulled out of the PDF
        object graph (including compressed streams and indirect references) and
        inspected statically. Nothing is executed.
        """
        try:
            chunks, stream_warnings = self._extract_js(pdf)
        except Exception as exc:
            # A structural failure must not silently hide ALL JavaScript
            # findings — "could not analyse" is visibly different from "clean".
            return [
                self._indicator(
                    "PDF_JS_PARSE_WARN",
                    "JavaScript-Extraktion fehlerhaft — JS-Analyse nicht gelaufen",
                    detail=(
                        f"{type(exc).__name__}: {exc} — die JS-Analyse ist "
                        "unvollständig; das Ergebnis ist nicht als 'sauber' zu werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_SCRIPT,
                    # 25, not 0: the comment above was always right — the
                    # weight was what made it a lie. SCORE_GREEN_MAX is 19, so
                    # weight 0 scored a PDF whose JavaScript was NEVER
                    # extracted as GREEN. The raw-byte triage cannot see JS
                    # that lives in a compressed /ObjStm, which is exactly the
                    # measured evasion.
                    weight=25,
                )
            ]
        # Cap the analysed text: .lower() would otherwise double the memory
        # of an oversized (attack) payload once more.
        js_text = "\n".join(chunks)[:_MAX_STREAM_BYTES]
        out: list[Indicator] = []
        if stream_warnings:
            bomb_suspected = any(_warn_is_bomb(w) for w in stream_warnings)
            # Runde 4: both branches are the same fact — the content of these
            # streams was NOT analysed. Measured before the fix: a merely
            # damaged /JS stream scored 0 (below SCORE_GREEN_MAX), the bomb 15.
            # So a PDF whose JavaScript sat in a stream the reader refused came
            # back GREEN, and the deliberate bomb weighed *more* than the
            # accident. One weight class (25) for "not read" — the title and the
            # severity distinguish the reason, no branch is the lighter one.
            out.append(
                self._indicator(
                    "PDF_JS_STREAM_WARN",
                    (
                        "JavaScript-Stream nur teilweise gelesen (Bomben-Verdacht)"
                        if bomb_suspected
                        else "JavaScript nicht vollständig analysiert"
                    ),
                    detail=(
                        "; ".join(stream_warnings[:3])
                        + " — der betroffene JavaScript-Code wurde nicht "
                        "analysiert; das Ergebnis ist nicht als 'sauber' zu werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_SCRIPT,
                    weight=25,
                )
            )
        if not js_text.strip():
            return out
        # Auto-exec context: JS wired to /OpenAction or a genuine /AA key
        # runs on open. Raw-byte checks miss object streams and encrypted
        # PDFs, so the object graph is consulted as well. The regex excludes
        # /AAPL:… names that macOS writes into every Quartz PDF (they would
        # escalate innocent JS to CRITICAL).
        auto_exec = (
            b"/OpenAction" in ctx.data
            or bool(_AA_KEY_RE.search(ctx.data))
            or self._root_has_auto_action(pdf)
        )
        out.extend(self._analyze_js_text(js_text, auto_exec))
        return out

    @staticmethod
    def _root_has_auto_action(pdf) -> bool:
        """Structural auto-exec context (ObjStm-safe).

        Checks the document root (/OpenAction, /AA) AND every page dict's
        /AA — a page-open action runs JS on merely VIEWING the page, which
        the raw-byte fallback cannot see when pages live in object streams.
        """
        import pikepdf

        try:
            root = pdf.Root
        except Exception:
            return False
        try:
            if pikepdf.Name.OpenAction in root:
                return True
        except Exception:
            pass
        try:
            if root.get(pikepdf.Name.AA) is not None:
                return True
        except Exception:
            pass
        try:
            page_iter = iter(pdf.pages)
        except Exception:
            return False
        while True:
            # Pull ONE page at a time: a corrupt page tree raises here (caught
            # below), and no huge PDF materialises all page handles at once.
            try:
                page = next(page_iter)
            except StopIteration:
                break
            except Exception:
                return False
            # Per-page try: one corrupt page dict must not hide /AA on the
            # remaining pages (fail-tolerant, like _layout_forensics).
            try:
                if pikepdf.Name.AA in page:
                    return True
            except Exception:
                continue
        return False

    # Bounds for the action-graph walk. Depth 16 is far beyond any real
    # action nesting (/OpenAction, /AA, /Annots/A are 1-3 levels deep); the
    # node budget stops a hostile object graph from turning the walk into an
    # unbounded traversal. Both are enforced per document.
    _GRAPH_MAX_DEPTH = 16
    _GRAPH_MAX_NODES = 200_000

    def _walk_action_graph(
        self, pdf, *, collect_js: bool, collect_uris: bool = False
    ) -> _GraphWalk:
        """Walk dictionaries/arrays reachable from the document action anchors.

        Returns a :class:`_GraphWalk` dataclass:

        * ``js_values``: value of every ``/JS``/``/JavaScript`` key found
          (direct or indirect; stream-/string-/array-shaped);
        * ``uri_values``: ``/URI`` targets (plus Catalog ``/URI << /Base ... >>``
          base strings when present; ``None`` sentinel on read error);
        * ``launch_hits``: number of Launch actions (``/S /Launch`` or a
          ``/Launch`` key) in the graph;
        * ``truncated``: the depth/node bound was hit, i.e. the graph was NOT
          fully inspected;
        * ``visited``: object ids already walked, so an indirect payload that
          is reachable twice is only collected/analysed once;
        * ``incomplete``: ``True`` when URIs were requested and neither the
          page tree nor the document root could be walked.

        Starting points are the page tree and the document root; the root
        walk reaches /OpenAction, /AA, /Names (JavaScript name tree) and
        /AcroForm, the page walk reaches /Annots. Streams are NOT traversed:
        their bytes are payload, not an object graph (a ``/JS`` stream value
        is still collected and read by :meth:`_js_value_text`).
        """
        import pikepdf

        js_values: list = []
        uri_values: list = []
        seen_uri_objgens: set[tuple[int, int]] = set()
        visited: set[tuple[int, int]] = set()
        state = {"nodes": 0, "launch": 0, "truncated": False}

        def _record_uri(val: object) -> None:
            uid = _identity(val)
            if uid is not None:
                if uid in seen_uri_objgens:
                    return
                seen_uri_objgens.add(uid)
            uri_values.append(val)

        def _identity(obj):
            try:
                if obj.is_indirect:
                    return obj.objgen
            except Exception:
                pass
            return None

        def _walk(obj, depth: int) -> None:
            if state["truncated"]:
                return
            state["nodes"] += 1
            if depth > self._GRAPH_MAX_DEPTH or state["nodes"] > self._GRAPH_MAX_NODES:
                state["truncated"] = True
                return
            if isinstance(obj, pikepdf.Stream):
                # The stream CONTENT is payload, never an object graph; only
                # the /JS value itself is decoded later.
                return
            ident = _identity(obj)
            if ident is not None:
                if ident in visited:
                    return
                visited.add(ident)
            if isinstance(obj, pikepdf.Array):
                try:
                    items = list(obj)
                except Exception:
                    return
                for item in items:
                    _walk(item, depth + 1)
                return
            # pikepdf.Page is an ObjectHelper, NOT a Dictionary subclass; its
            # underlying page dictionary is ``page.obj``.
            if not isinstance(obj, pikepdf.Dictionary):
                return
            try:
                keys = list(obj.keys())
            except Exception:
                return
            key_names = {str(key) for key in keys}
            is_launch = "/Launch" in key_names
            if not is_launch:
                try:
                    is_launch = (
                        obj.get(pikepdf.Name("/S")) == pikepdf.Name("/Launch")
                    )
                except Exception:
                    is_launch = False
            if is_launch:
                state["launch"] += 1
            # Collect THIS dictionary's JS carriers before descending into
            # its other values: the old whole-object pass checked /JS and
            # /JavaScript first, so a shallow payload keeps being analysed
            # before a deeply nested one (budget order stays predictable).
            if collect_js:
                for js_key in (pikepdf.Name.JS, pikepdf.Name.JavaScript):
                    if js_key in keys:
                        with suppress(Exception):
                            js_values.append(obj.get(js_key))
            if collect_uris and pikepdf.Name.URI in keys:
                try:
                    uri_obj = obj.get(pikepdf.Name.URI)
                except Exception:
                    # Broken indirect /URI reference must never vanish silently:
                    # append None sentinel so _link_indicators emits PDF_PARSE_WARN.
                    uri_values.append(None)
                else:
                    if isinstance(uri_obj, pikepdf.Dictionary):
                        # ISO 32000-1 §12.6.4.7: Document Catalog /URI << /Base (...) >>
                        # is a standard dictionary, not a malformed URI string.
                        if pikepdf.Name.Base in uri_obj:
                            try:
                                base_val = uri_obj.get(pikepdf.Name.Base)
                            except Exception:
                                uri_values.append(None)
                            else:
                                _record_uri(base_val)
                    else:
                        _record_uri(uri_obj)
            for key in keys:
                try:
                    value = obj.get(key)
                except Exception:
                    continue
                # The /JS value was collected above; walking it still reaches
                # actions below a /JavaScript NAME TREE (the key also names a
                # container). _js_value_text ignores container shapes.
                _walk(value, depth + 1)

        # Page tree first: a page dict also carries /Annots (and its /A
        # actions). The root walk then reaches the rest and skips every
        # indirect page it already saw.
        try:
            for page in pdf.pages:
                try:
                    page_dict = page.obj
                except Exception:
                    page_dict = page
                _walk(page_dict, 0)
                if state["truncated"]:
                    break
        except Exception:
            pass
        if not state["truncated"]:
            try:
                root = pdf.Root
            except Exception:
                root = None
            if root is not None:
                _walk(root, 0)
        graph_incomplete = bool(collect_uris and not visited and not state["truncated"])
        return _GraphWalk(
            js_values=js_values,
            uri_values=uri_values,
            launch_hits=state["launch"],
            truncated=bool(state["truncated"]),
            visited=visited,
            incomplete=graph_incomplete,
        )

    def _link_indicators(self, uri_values: list) -> list[Indicator]:
        """Decode structural PDF ``/URI`` values and check them against local blocklists."""
        cap = config.BINARY_IOC_MAX_HITS
        urls: list[str] = []
        seen: set[str] = set()
        capped = False
        raw_capped = False
        unreadable = 0

        # Hard ceiling on raw /URI decodings even when all entries are direct
        # duplicates, namespaces, or unreadable objects (prevents CPU amplification).
        max_raw_entries = max(cap * 20, 4_000)
        for idx, raw in enumerate(uri_values):
            if idx >= max_raw_entries:
                raw_capped = True
                break
            url = _decode_pdf_uri(raw)
            if url is None:
                unreadable += 1
                continue
            if is_namespace_host(url):
                continue
            key = url.lower()
            if key in seen:
                continue
            if cap > 0 and len(urls) >= cap:
                capped = True
                break
            seen.add(key)
            urls.append(url)

        out: list[Indicator] = []
        if unreadable:
            out.append(
                self._indicator(
                    "PDF_PARSE_WARN",
                    f"Nicht lesbare PDF-Links (/URI) ({unreadable})",
                    detail=(
                        f"{unreadable} /URI-Eintrag/-Einträge im PDF ließen sich "
                        "nicht dekodieren und wurden daher NICHT geprüft."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_STRUCTURE,
                    weight=20,
                )
            )
        if capped or raw_capped:
            cap_reason = (
                f"Das PDF enthält mehr als {max_raw_entries} rohe /URI-Einträge."
                if raw_capped and not capped
                else f"Das PDF enthält mehr als {cap} eindeutige Links (/URI)."
            )
            out.append(
                self._indicator(
                    "PDF_LINK_CAPPED",
                    "PDF-Link-Prüfung durch Trefferdeckel begrenzt",
                    detail=(
                        f"{cap_reason} Weitere Links wurden nicht geprüft — "
                        "das Ergebnis ist daher nicht vollständig."
                    ),
                    severity=Severity.INFO,
                    category=CAT_IOC,
                    weight=0,
                )
            )
        if not urls:
            return out

        hits = [(IOC_URL, url) for url in urls]
        blocked, plain, unavailable = split_blocked_iocs(hits)

        for rule_id, detail in unavailable:
            out.append(
                self._indicator(
                    rule_id,
                    BLOCKLIST_UNAVAILABLE_TITLE,
                    detail=detail + " Das Ergebnis ist an dieser Stelle unvollständig.",
                    severity=Severity.INFO,
                    category=CAT_IOC,
                    weight=0,
                )
            )

        if blocked:
            shown = ", ".join(
                f"{defang_url(url)} ({host_of_url(url) or 'Host unbekannt'})"
                for _kind, url in blocked[:10]
            )
            extra = f" (+{len(blocked) - 10} weitere)" if len(blocked) > 10 else ""
            out.append(
                self._indicator(
                    "BINARY_IOC_BLOCKED",
                    f"{BINARY_IOC_BLOCKED_TITLE} ({len(blocked)})",
                    detail=(
                        "Link in der PDF-Struktur (/Annots -> /A -> /URI) steht "
                        f"auf der lokalen Blocklist: {shown}{extra}"
                    ),
                    severity=Severity.HIGH,
                    category=CAT_IOC,
                    weight=30,
                )
            )

        if plain:
            shown = ", ".join(defang_url(url) for _kind, url in plain[:10])
            extra = f" (+{len(plain) - 10} weitere)" if len(plain) > 10 else ""
            qualifier = (
                "Ein Teil der lokalen Blocklisten war nicht lesbar; dieser "
                "Hinweis ist daher nicht vollständig."
                if unavailable
                else "Kein Eintrag auf einer lokalen Blocklist — Hinweis ohne Einfluss auf die Bewertung."
            )
            out.append(
                self._indicator(
                    "PDF_LINK",
                    f"Links im PDF ({len(plain)})",
                    detail=(
                        f"Strukturelle Links in der PDF-Struktur (/URI): {shown}{extra}. "
                        f"{qualifier}"
                    ),
                    severity=Severity.INFO,
                    category=CAT_IOC,
                    weight=0,
                )
            )
        return out

    # -- stage 2b: embedded JavaScript ------------------------------------- #

    def _extract_js(self, pdf) -> tuple[list[str], list[str]]:
        """Collect embedded JavaScript code from the PDF (decompressed).

        Returns ``(chunks, stream_warnings)``: streams whose decompressed
        size exceeds the bomb limit are refused with a warning instead of
        being materialised in full (OOM protection). Collection stops as
        soon as the accumulated text reaches the analysis budget — the
        per-stream cap alone would not bound the SUM over many streams,
        and the budget is shared THROUGH the recursion so a single /JS
        array of many strings cannot bypass it either.

        Direct action dictionaries (``/OpenAction << /S /JavaScript /JS … >>``,
        annotation ``/A``, the JavaScript name tree) are part of their parent
        object and were invisible to the old ``pdf.objects`` loop; the bounded
        graph walk reaches them (BUG-016). The old whole-object pass stays as
        a fallback for action objects that are NOT reachable from the root
        (e.g. a damaged page tree), skipping everything already walked.
        """
        import pikepdf

        chunks: list[str] = []
        warnings: list[str] = []
        total_ref = [0]
        walk = self._walk_action_graph(pdf, collect_js=True)
        js_values = walk.js_values
        visited = walk.visited
        for value in js_values:
            if total_ref[0] >= _MAX_STREAM_BYTES:
                break
            self._js_value_text(
                value, pikepdf, depth=0, chunks=chunks,
                warnings=warnings, total_ref=total_ref,
            )
        if total_ref[0] >= _MAX_STREAM_BYTES:
            # Budget exhaustion MUST be visible: an attacker can pad with
            # 8 MiB of harmless JS and hide a malicious /JS behind it —
            # silently dropping that is an evasion vector (hunt finding 3.1).
            warnings.append(
                f"JS-Gesamtbudget ({_MAX_STREAM_BYTES} Bytes) erschöpft "
                "— weitere /JS-Inhalte wurden nicht analysiert; das "
                "Ergebnis ist nicht als 'sauber' zu werten."
            )
            return chunks, warnings
        for obj in pdf.objects:
            if obj is None:
                continue
            try:
                if obj.is_indirect and obj.objgen in visited:
                    continue
            except Exception:
                continue
            try:
                keys = list(obj.keys())
            except Exception:
                continue
            for key in (pikepdf.Name.JS, pikepdf.Name.JavaScript):
                if key not in keys:
                    continue
                try:
                    value = obj.get(key)
                except Exception:
                    continue
                self._js_value_text(
                    value, pikepdf, depth=0, chunks=chunks,
                    warnings=warnings, total_ref=total_ref,
                )
                if total_ref[0] >= _MAX_STREAM_BYTES:
                    # Budget exhaustion MUST be visible: an attacker can pad
                    # with 8 MiB of harmless JS and hide a malicious /JS
                    # behind it — silently dropping that is an evasion
                    # vector (hunt finding 3.1).
                    warnings.append(
                        f"JS-Gesamtbudget ({_MAX_STREAM_BYTES} Bytes) erschöpft "
                        "— weitere /JS-Inhalte wurden nicht analysiert; das "
                        "Ergebnis ist nicht als 'sauber' zu werten."
                    )
                    return chunks, warnings
        return chunks, warnings

    @staticmethod
    def _js_value_text(
        value, pikepdf, depth: int, chunks: list, warnings: list, total_ref: list
    ) -> None:
        """Render a ``/JS`` value (stream, string or array of those) as text.

        ``total_ref[0]`` tracks the cumulative character count across the
        whole recursion; every append respects the remaining budget.
        """

        def _as_text(raw: bytes) -> str:
            # PDF strings may be UTF-16BE with a BOM; decoding those as
            # latin-1 garbles every second character and loses API hits.
            if raw.startswith(b"\xfe\xff"):
                return raw[2:].decode("utf-16-be", errors="ignore")
            return raw.decode("latin-1", "ignore")

        if depth > 4:
            # BUG-023: a bound that silently drops payload is an evasion
            # vector — the caller must be able to say "not examined".
            note = (
                "Verschachteltes /JS jenseits der Analysetiefe 4 wurde NICHT "
                "analysiert — das Ergebnis ist nicht als 'sauber' zu werten."
            )
            if note not in warnings:
                warnings.append(note)
            return
        if total_ref[0] >= _MAX_STREAM_BYTES:
            # defensive: bound recursive structures AND the shared budget
            return
        try:
            if isinstance(value, pikepdf.Stream):
                payload, warn = _read_stream_bounded(value, pikepdf)
                if warn is not None:
                    warnings.append(warn)
                if payload:
                    # Analyse the readable prefix EVEN when warned: a
                    # truncated stream still typically contains the whole
                    # payload, and discarding it would let an attacker hide
                    # JS by simply cutting the stream's last bytes. The
                    # warning keeps the "not fully analysed" caveat visible.
                    full_text = _as_text(payload)
                    budget_left = _MAX_STREAM_BYTES - total_ref[0]
                    text = full_text[:budget_left]
                    if text:
                        chunks.append(text)
                        total_ref[0] += len(text)
                    if len(text) < len(full_text):
                        # Truncatur am Budget: der Rest dieses Streams (und
                        # alle folgenden) werden nicht analysiert — sichtbar
                        # melden statt still verwerfen (Evasions-Vektor,
                        # Hunt-Fund 3.1).
                        warnings.append(
                            f"JS-Gesamtbudget ({_MAX_STREAM_BYTES} Bytes) erschöpft "
                            "— dieser /JS-Stream wurde gekürzt; weitere Inhalte "
                            "wurden nicht analysiert."
                        )
                return
            if isinstance(value, pikepdf.Array):
                for item in value:
                    if total_ref[0] >= _MAX_STREAM_BYTES:
                        return
                    PdfPipeline._js_value_text(
                        item, pikepdf, depth + 1, chunks, warnings, total_ref
                    )
                return
            if isinstance(value, pikepdf.String):
                text = _as_text(bytes(value))[: _MAX_STREAM_BYTES - total_ref[0]]
                if text:
                    chunks.append(text)
                    total_ref[0] += len(text)
            # Dictionaries/other shapes are not valid JS carriers; ignore.
        except Exception:
            return

    def _analyze_js_text(self, js_text: str, auto_exec: bool) -> list[Indicator]:
        """Static content analysis of extracted JavaScript (no execution)."""
        out: list[Indicator] = []
        lowered = js_text.lower()
        excerpt = js_text.strip()[:200]

        # Informational: JS was present and inspected (no score impact — the
        # keyword triage already signals mere presence; the value here is the
        # content analysis below).
        out.append(
            self._indicator(
                "PDF_JS_EXTRACTED",
                f"Eingebettetes JavaScript extrahiert ({len(js_text)} Zeichen)",
                detail="JavaScript-Code wurde aus dem PDF dekomprimiert und statisch "
                       "geprüft (nicht ausgeführt). Anfang: " + excerpt,
                severity=Severity.INFO,
                category=CAT_SCRIPT,
                weight=0,
            )
        )

        boese = sorted({api for api in _PDF_JS_MALICIOUS if api in lowered})
        if boese:
            out.append(
                self._indicator(
                    "PDF_JS_SUSPICIOUS",
                    "Bösartige JavaScript-APIs: " + ", ".join(boese),
                    detail=(
                        "Das eingebettete JavaScript nutzt Ausführungs-/Exfiltrations- "
                        "oder bekannte Exploit-Primitive"
                        + (", gekoppelt an eine Auto-Start-Aktion (/OpenAction, /AA)."
                           if auto_exec else ".")
                    ),
                    severity=Severity.CRITICAL if auto_exec else Severity.HIGH,
                    category=CAT_SCRIPT,
                    weight=50 if auto_exec else 30,
                )
            )

        # Dokumentuebliche APIs: sichtbar, aber kein Anker. Ein Formular, das
        # einen Link oeffnet oder sich absendet, ist kein Angriff.
        ueblich = sorted({api for api in _PDF_JS_COMMON if api in lowered})
        if ueblich:
            out.append(
                self._indicator(
                    "PDF_JS_DOC_API",
                    "Dokumentübliche JavaScript-APIs: " + ", ".join(ueblich),
                    detail=(
                        "Diese APIs sind in Formularen und verlinkten Dokumenten "
                        "alltäglich (Link öffnen, Formular absenden, Anmerkung "
                        "lesen). Sie allein sind kein Hinweis auf eine Schadwirkung."
                    ),
                    severity=Severity.INFO,
                    category=CAT_SCRIPT,
                    # 0: the detail text already says it — these APIs alone
                    # are not a finding. On the VA form 21-526ez this added
                    # 10 points to /JS and an incomplete graph walk and made
                    # a benign form RED.
                    weight=0,
                )
            )

        obf_hits = sorted({o for o in _PDF_JS_OBFUSCATION if o in lowered})
        if obf_hits:
            out.append(
                self._indicator(
                    "PDF_JS_OBFUSCATED",
                    "Verschleiertes JavaScript: " + ", ".join(obf_hits),
                    detail="Der JavaScript-Code nutzt Verschleierung (z. B. "
                           "String.fromCharCode/unescape), um den Payload zu verbergen.",
                    severity=Severity.HIGH,
                    category=CAT_SCRIPT,
                    weight=30,
                )
            )

        # AP13: decode the hiding primitives statically and re-check the
        # payload. Only a MALICIOUS primitive that was not visible in the
        # original text is a new statement; harmless form JS that uses
        # fromCharCode for a greeting stays without this finding.
        decoded = deobfuscate_js(js_text)
        if decoded != js_text:
            decoded_lower = decoded.lower()
            revealed = sorted(
                {
                    api
                    for api in _PDF_JS_MALICIOUS
                    if api in decoded_lower and api not in lowered
                }
            )
            if revealed:
                excerpt = decoded.strip()[:200]
                # BUG-017: obfuscation must never TURN a verdict around. The
                # same payload scored CRITICAL/50 when written as plain
                # ``eval(...)`` and only MEDIUM/15 when written as
                # ``"ev"+"al(...)"`` — 15 < SCORE_GREEN_MAX (19), so hiding
                # the primitive made the file GREEN. A primitive revealed
                # only after decoding is at least as suspicious as the one
                # that was readable all along: same rating as
                # PDF_JS_SUSPICIOUS.
                out.append(
                    self._indicator(
                        "PDF_JS_DEOBFUSCATED",
                        "Verschleiertes JavaScript enthält bösartige API: "
                        + ", ".join(revealed),
                        detail=(
                            "Nach statischer Dekodierung (keine Ausführung) "
                            "wurden bislang verborgene Primitive sichtbar: "
                            + ", ".join(revealed)
                            + ". Dekodierter Anfang: " + excerpt
                        ),
                        severity=Severity.CRITICAL if auto_exec else Severity.HIGH,
                        category=CAT_SCRIPT,
                        weight=50 if auto_exec else 30,
                    )
                )
        return out

    # -- stage 3: layout forensics ----------------------------------------- #

    def _layout_forensics(self, ctx: AnalysisContext, pdf) -> list[Indicator]:
        import pikepdf

        out: list[Indicator] = []
        try:
            invisible_pages: list[int] = []
            color_on_color_pages: list[int] = []
            stream_warnings: list[str] = []
            unreadable_pages: list[int] = []
            # PERF-002: the per-stream cap does not bound the SUM over pages.
            # One budget is shared across every stream of every page; the
            # first page/stream that would exceed it stops the stage.
            layout_budget = _MAX_LAYOUT_BYTES
            budget_exhausted_at: int | None = None
            for page_index, page in enumerate(pdf.pages):
                if layout_budget <= 0:
                    budget_exhausted_at = page_index + 1
                    break
                try:
                    contents = page.get(pikepdf.Name.Contents)
                    if contents is None:
                        continue
                    parts: list[bytes] = []
                    streams = (
                        list(contents)
                        if isinstance(contents, pikepdf.Array)
                        else [contents]
                    )
                    for stream in streams:
                        if layout_budget <= 0:
                            # Remaining streams of this page are NOT read.
                            budget_exhausted_at = page_index + 1
                            break
                        payload, warn = _read_stream_bounded(stream, pikepdf)
                        if warn is not None:
                            stream_warnings.append(f"S. {page_index + 1}: {warn}")
                        if payload:
                            # Analyse the readable prefix EVEN when warned —
                            # same contract as _js_value_text: a truncated
                            # stream still typically contains the whole
                            # content; discarding it would let an attacker
                            # hide invisible text by cutting the stream tail.
                            # The budget is charged BEFORE the payload is kept:
                            # it bounds live memory, it is not a statistic
                            # computed after the fact.
                            layout_budget -= len(payload)
                            parts.append(payload)
                    content = b"".join(parts)
                except Exception:
                    # Runde 4: this used to be a bare `continue` — the page
                    # vanished without a trace, so a PDF whose pages are all
                    # built this way ran the whole layout stage on nothing and
                    # still scored GREEN. Per-page failures stay contained (one
                    # broken page must not stop the others), but they are
                    # collected and reported once below.
                    unreadable_pages.append(page_index + 1)
                    continue
                if not content:
                    continue
                # Text rendering mode 3 = neither fill nor stroke (invisible).
                if re.search(rb"(^|\s)3\s+Tr\b", content):
                    invisible_pages.append(page_index + 1)
                # Conservative color-on-color heuristic: a white fill combined
                # with a text-show operator in the same stream. The TJ pattern
                # matches bracket pairs without crossing into other arrays and
                # tolerates line breaks inside the array (content streams are
                # routinely wrapped); unlike `.*?` it stays linear even when a
                # `[` is never closed.
                # GEMESSEN, und die alte Fassung war zu weit: sie verlangte
                # nur "irgendwo auf der Seite eine weisse Fuellung" UND
                # "irgendwo Text". Damit feuerte sie auf JEDEM echten
                # Behoerdenformular (IRS, VA, GSA) — ein weisses Eingabefeld
                # neben normalem Text genuegt. Color-on-Color heisst aber, dass
                # der Text MIT der weissen Fuellung gezeichnet wird, also
                # unsichtbar ist.
                #
                # Deshalb NAEHE statt Beliebigkeit: die Fuellung muss dem
                # Textoperator unmittelbar vorausgehen. Das ist genau die
                # Steganografie-Technik ("weisser Text auf weissem Grund") und
                # trifft ein normales Layout nicht mehr.
                scan_window = content[: config.MAX_CONTENT_SCAN_SIZE]
                if _hat_weissen_text(scan_window):
                    color_on_color_pages.append(page_index + 1)

            if invisible_pages:
                out.append(
                    self._indicator(
                        "PDF_INVISIBLE_TEXT",
                        f"Unsichtbarer Text (Render Mode 3) auf S. {invisible_pages[:10]}",
                        detail=(
                            "Text mit Text-Rendering-Modus 3 wird nicht gezeichnet und ist "
                            "für den Betrachter unsichtbar — häufig in Phishing/Spam."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_STEGO,
                        weight=15,
                    )
                )
            if color_on_color_pages:
                out.append(
                    self._indicator(
                        "PDF_COLOR_ON_COLOR",
                        f"Weißer Text auf S. {color_on_color_pages[:10]}",
                        detail=(
                            "Der letzte Farboperator vor einem Textoperator war "
                            "weiß — der Text ist damit auf weißem Grund unsichtbar. "
                            "Das ist die klassische Steganografie-Technik, aber "
                            "NICHT unterscheidbar von einem Formularfeld: die "
                            "IRS-Formulare zeichnen Feldbeschriftungen wie "
                            "'Schedule B' genau so und legen später eine farbige "
                            "Fläche darüber. GEMESSEN auf 13 echten "
                            "Behoerdenformularen und 25 arXiv-PDFs. Deshalb kein "
                            "Gewicht: der Befund bleibt sichtbar und die Fläche "
                            "ist im Bericht nachlesbar, aber er traegt kein Urteil."
                        ),
                        severity=Severity.LOW,
                        category=CAT_STEGO,
                        weight=0,
                    )
                )
            if budget_exhausted_at is not None:
                # PERF-002: stopping early is an honest "not checked", never a
                # silent truncation — otherwise a crafted PDF could bury its
                # hidden text behind cheap padding pages and still look clean.
                out.append(
                    self._indicator(
                        "PDF_PARSE_WARN",
                        "Layout-Forensik abgebrochen — Dekompressionsbudget "
                        f"erschöpft (ab S. {budget_exhausted_at})",
                        detail=(
                            "Die Inhalts-Streams überschritten das Gesamtbudget "
                            f"von {_MAX_LAYOUT_BYTES} dekomprimierten Bytes; "
                            "weitere Streams/Seiten wurden NICHT auf "
                            "unsichtbaren Text und Color-on-Color geprüft. Das "
                            "Ergebnis ist nicht als 'sauber' zu werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_STEGO,
                        weight=25,
                    )
                )
            if stream_warnings:
                bomb_suspected = any(_warn_is_bomb(w) for w in stream_warnings)
                # Same contract as PDF_JS_STREAM_WARN: the content of these
                # streams was not read, so the layout heuristics did not run on
                # them. Both branches cost 25 — measured before the fix: the
                # non-bomb branch scored 0 and a PDF with an unreadable content
                # stream stayed GREEN.
                out.append(
                    self._indicator(
                        "PDF_STREAM_WARN",
                        (
                            "Inhalts-Stream nur teilweise gelesen (Bomben-Verdacht)"
                            if bomb_suspected
                            else "Inhalts-Stream nicht gelesen"
                        ),
                        detail=(
                            "; ".join(stream_warnings[:3])
                            + " — die Layout-Forensik ist für diese Seiten "
                            "unvollständig; das Ergebnis ist nicht als 'sauber' "
                            "zu werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_STEGO,
                        weight=25,
                    )
                )
            if unreadable_pages:
                # ONE indicator for all skipped pages: the fact is "the stage
                # did not run for these pages", not one finding per page.
                out.append(
                    self._indicator(
                        "PDF_PAGE_SKIP_WARN",
                        f"Seiten nicht prüfbar ({len(unreadable_pages)}): "
                        f"S. {unreadable_pages[:10]}",
                        detail=(
                            "Der Inhalts-Stream dieser Seiten liess sich nicht "
                            "lesen — unsichtbarer Text und Color-on-Color wurden "
                            "dort NICHT geprüft; das Ergebnis ist nicht als "
                            "'sauber' zu werten."
                        ),
                        severity=Severity.MEDIUM,
                        category=CAT_STEGO,
                        weight=25,
                    )
                )
        except Exception as exc:
            # A page-tree walk failure used to be swallowed by a bare `pass`:
            # the stage produced NO indicator at all, so a PDF whose
            # invisible-text / color-on-color / content-stream analysis never
            # ran still scored GREEN. Per-page read failures stay contained by
            # the inner `except: continue`; this outer handler only sees a
            # failure of the stage as a whole. Same lower bound as the other
            # stage-outage warnings: 25, because SCORE_GREEN_MAX is 19.
            out.append(
                self._indicator(
                    "PDF_PARSE_WARN",
                    "Layout-Forensik fehlerhaft — unsichtbarer Text nicht geprüft",
                    detail=(
                        f"{type(exc).__name__}: {exc} — die Layout-Stufe "
                        "(unsichtbarer Text, Color-on-Color) lief NICHT; das "
                        "Ergebnis ist nicht als 'sauber' zu werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_STEGO,
                    weight=25,
                )
            )
        return out
