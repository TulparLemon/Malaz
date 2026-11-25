"""Static PDF analysis pipeline.

Runs in four stages, each strictly bounded and non-executing:
1. Fast byte-level keyword triage (works even on broken/encrypted PDFs).
2. Structural analysis via ``pikepdf`` (XREF, object streams, incremental
   saves, action-graph and link checks via :mod:`malaz.pipelines.pdf_links`).
3. Embedded JavaScript extraction and static deobfuscation via
   :mod:`malaz.pipelines.pdf_javascript`.
4. Content-stream layout forensics (invisible text render mode / white-on-white).

Low-level stream decompression and bomb guards live in
:mod:`malaz.pipelines.pdf_streams`; all previously public and tested symbols
remain bound on this facade module.
"""

from __future__ import annotations

import io
import re
from contextlib import suppress
from pathlib import PurePosixPath

from .. import config
from ..core.risky_types import RISKY_SUFFIXES
from ..models import (
    CAT_SCRIPT,
    CAT_STEGO,
    CAT_STRUCTURE,
    AnalysisContext,
    Indicator,
    Severity,
)
from . import pdf_qr
from .base import Pipeline
from .pdf_javascript import (
    _PDF_JS_COMMON as _PDF_JS_COMMON,
)
from .pdf_javascript import (
    _PDF_JS_MALICIOUS as _PDF_JS_MALICIOUS,
)
from .pdf_javascript import (
    _PDF_JS_OBFUSCATION as _PDF_JS_OBFUSCATION,
)
from .pdf_javascript import (
    analyze_js_text,
    extract_pdf_js,
    root_has_auto_action,
    scan_pdf_javascript,
)
from .pdf_links import (
    GRAPH_MAX_DEPTH,
    GRAPH_MAX_NODES,
    build_link_indicators,
    decode_pdf_uri,
    walk_action_graph,
)
from .pdf_links import (
    _GraphWalk as _GraphWalk,
)
from .pdf_streams import (
    _AA_KEY_RE as _AA_KEY_RE,
)
from .pdf_streams import (
    MAX_STREAM_BYTES,
    chain_expansion,
    read_pdf_text_value,
    read_stream_bounded,
    warn_is_bomb,
)

# Compatibility bindings on the facade module (PEP-484 / Ruff F401 safe).
_MAX_STREAM_BYTES = MAX_STREAM_BYTES
_chain_expansion = chain_expansion
_warn_is_bomb = warn_is_bomb
_decode_pdf_uri = decode_pdf_uri


def _read_stream_bounded(stream, pikepdf) -> tuple[bytes | None, str | None]:
    """Facade wrapper honoring monkeypatches on ``pdf_pipeline._MAX_STREAM_BYTES``."""
    return read_stream_bounded(stream, pikepdf, max_stream_bytes=_MAX_STREAM_BYTES)

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
                indicators.extend(pdf_qr.scan_pdf_qr(pdf))
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
        return scan_pdf_javascript(
            ctx,
            pdf,
            source=self.name,
            max_stream_bytes=_MAX_STREAM_BYTES,
            extract_fn=self._extract_js,
        )

    @staticmethod
    def _root_has_auto_action(pdf) -> bool:
        return root_has_auto_action(pdf)

    _GRAPH_MAX_DEPTH = GRAPH_MAX_DEPTH
    _GRAPH_MAX_NODES = GRAPH_MAX_NODES

    def _walk_action_graph(
        self, pdf, *, collect_js: bool, collect_uris: bool = False
    ) -> _GraphWalk:
        return walk_action_graph(
            pdf,
            collect_js=collect_js,
            collect_uris=collect_uris,
            max_depth=self._GRAPH_MAX_DEPTH,
            max_nodes=self._GRAPH_MAX_NODES,
        )

    def _link_indicators(self, uri_values: list) -> list[Indicator]:
        return build_link_indicators(uri_values, source=self.name)

    def _extract_js(self, pdf) -> tuple[list[str], list[str]]:
        return extract_pdf_js(
            pdf,
            max_stream_bytes=_MAX_STREAM_BYTES,
            max_depth=self._GRAPH_MAX_DEPTH,
            max_nodes=self._GRAPH_MAX_NODES,
        )

    @staticmethod
    def _js_value_text(
        value,
        pikepdf,
        depth: int,
        chunks: list,
        warnings: list,
        total_ref: list,
    ) -> None:
        read_pdf_text_value(
            value,
            pikepdf,
            depth,
            chunks,
            warnings,
            total_ref,
            max_stream_bytes=_MAX_STREAM_BYTES,
        )

    def _analyze_js_text(self, js_text: str, auto_exec: bool) -> list[Indicator]:
        return analyze_js_text(js_text, auto_exec, source=self.name)


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
