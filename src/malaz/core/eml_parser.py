"""MIME, header, address, Received-chain, and link parsing for email files.

Extracted from :mod:`malaz.core.eml_analysis` (Spec 012, Etappe 1) so parsing
and static security heuristics live in separate, cohesive modules. All public
symbols remain re-exported from :mod:`malaz.core.eml_analysis`.
"""

from __future__ import annotations

import ipaddress
import re
from bisect import bisect_left
from collections.abc import Iterator
from dataclasses import dataclass, field
from email.message import Message
from email.parser import BytesParser
from email.policy import default as default_policy
from email.utils import getaddresses
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .. import config
from .email_extract import mime_depth_note

# --------------------------------------------------------------------------- #
# Limits (all bounds are load-bearing: a crafted mail must not stall the scan)
# --------------------------------------------------------------------------- #

_MAX_HEADER_LINES = 400
_MAX_BODY_BYTES = 512 * 1024
_MAX_LINKS = 40
_MAX_HTML_STRIP_CHARS = 512 * 1024
# The header block is attacker-controlled and was parsed without a cap:
# measured, a 5 MB single header cost ~50 MB of transient memory and a 20 MB
# one ~200 MB / 1.17 s — per worker (audit SEC-034). 256 KiB is far above any
# RFC-compliant header block while keeping the split/findall/parse cost flat.
_MAX_HEADER_BLOCK_BYTES = 256 * 1024


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class MailFacts:
    """Everything the pipeline learned about one mail (all fields optional)."""

    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    to_addr: str = ""
    message_id: str = ""
    received_count: int = 0
    # Die Kette selbst, nicht nur ihre Laenge: die Behauptungen in den
    # uebrigen Kopfzeilen lassen sich nur gegen sie pruefen.
    received_hops: list[ReceivedHop] = field(default_factory=list)
    # Die Behauptung "authentifiziert" ist nur so viel wert wie die Frage, ob
    # der Server, der sie ausgestellt haben will, ueberhaupt in der Kette steht.
    auth_claimed_by: str = ""
    # Die signierende Domain (d=) und der Selektor (s=) aus DKIM-Signature.
    # Die Signatur selbst laesst sich OHNE Netz nicht pruefen — es fehlt der
    # oeffentliche Schluessel aus dem DNS. Ausgelesen wird sie trotzdem: d=
    # gegen die From-Domain zu stellen ist eine lokale Aussage.
    dkim_domain: str = ""
    dkim_selector: str = ""
    # Kopfzeilen, in denen ein Filter- oder Gateway-Server sein Urteil
    # hinterlaesst. ALLE angreiferkontrolliert: eine Mail, die nie durch
    # Microsoft 365 lief, kann den SCL selbst hineinschreiben. Sie werden
    # deshalb als Behauptung gefuehrt und gegen die Received-Kette geprueft.
    filter_claims: dict[str, str] = field(default_factory=dict)
    # Der Date-Kopf (vom Absender gesetzt) gegen den Zeitstempel der ersten
    # Zustellung. Eine grosse Luecke heisst: die Mail lag lange, oder der
    # Zeitstempel wurde nachtraeglich gesetzt.
    date_header: str = ""
    auth_results: str = ""
    # One verdict per mechanism: "pass" | "fail" | "none" | "unknown".
    # "none" is the case the viewer must show explicitly — a sender that does
    # not use SPF/DKIM/DMARC at all is not the same as one that passed, and
    # silence about it read like approval.
    auth_verdicts: dict[str, str] = field(default_factory=dict)
    # Traegt die Mail LISTEN-Kopfzeilen (RFC 2919)? Dann sind mehrere
    # Auffaelligkeiten, die sonst fuer eine Faelschung sprechen, ihr
    # NORMALZUSTAND — siehe _analyze_headers.
    is_mailing_list: bool = False
    text_body: str = ""
    html_body: str = ""
    attachment_names: list[str] = field(default_factory=list)
    # Filled by the parser (parse_mail/parse_msg) with extract_links() over
    # both bodies. Renderers must REUSE this list: re-extracting on every
    # render made the link scan run twice per mail (see core/mail_view).
    links: list[LinkFacts] = field(default_factory=list)
    parse_error: str = ""
    # True when the header block exceeded _MAX_HEADER_BLOCK_BYTES and only its
    # prefix was analysed. Rendered as a visible note in analyze_structure.
    header_truncated: bool = False
    # The MIME walk hit MAIL_MAX_MIME_PARTS with parts still on the stack.
    # That is "the rest was not inspected", not "nothing found" (BUG-065).
    parts_truncated: bool = False
    html_body_truncated: bool = False


@dataclass
class ReceivedHop:
    """Eine Station aus der ``Received:``-Kette (Reihenfolge wie im Kopf).

    RFC 5321 schreibt die Kette in umgekehrter Reihenfolge: der ERSTE Eintrag
    ist die Station, die zuletzt zugestellt hat. Fuer die Frage "woher kam die
    Mail wirklich" ist der LETZTE Eintrag der interessante - dort steht die
    IP, mit der sich der Absender verbunden hat.
    """

    from_host: str = ""
    by_host: str = ""
    ip: str = ""
    protocol: str = ""
    stamp: str = ""
    # Aus dem Klammerzusatz "(using TLSv1.2 with cipher ...)"; Behauptung.
    tls: str = ""


@dataclass
class LinkFacts:
    """One URL found in the body, with its presentation context."""

    url: str = ""
    display_text: str = ""
    host: str = ""
    scheme: str = ""
    is_ip_literal: bool = False
    is_punycode: bool = False
    is_shortener: bool = False
    has_credentials: bool = False
    risky_tld: bool = False
    mismatch: bool = False  # display text names a different host
    reputation: str = ""  # filled by the optional opt-in lookup


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

_URL_RE = re.compile(
    # The plain class stops at ']' (it terminates Markdown/JSON runs), which
    # truncated an IPv6 authority to "http://[2001:db8::1" — urlsplit then
    # reported an EMPTY host and the IP-literal classification was lost
    # (BUG-073). A bracketed authority is therefore matched as a unit; URLs
    # that do not start with "[" keep the old boundary behaviour.
    r"\bhttps?://(?:\[[0-9A-Fa-f:.]+\][^\s<>\"'\)\]\}]*|[^\s<>\"'\)\]\}]+)",
    re.IGNORECASE,
)
# A scheme-less anchor target ("firma.de/pfad"). The last label must be
# alphabetic (or an IPv4 literal) — that is what separates a host from the
# relative file paths that must NOT become links ("images/logo.png" has no dot
# in its first segment, "v1.2/app.js" ends in a digit, "rechnung.eml/x" is a
# file name). A dot alone would flag them all.
_SCHEMELESS_HREF_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,}|xn--[a-z0-9-]+)"
    r"(?::\d{1,5})?/"
    r"|^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?/",
    re.IGNORECASE,
)
# <a ...>display</a> — the classic mismatch carrier. Three patterns instead of
# one, because the old single pattern ended on '(?P<text>.*?)</a>' with
# re.DOTALL: an HTML body without a single '</a>' made every '<a' candidate
# backtrack to the end of the (up to 512 KiB) body — O(n) per candidate, O(n^2)
# per mail. Measured on the old pattern: 32 KiB body 3.1 s, 256 KiB 188 s,
# against 0.016 s for the same byte count with closed anchors.
#
# What bounds it now: no part of a candidate may look past the next '<', and
# the closing tag is looked up in an index (see _iter_anchors) instead of by
# scanning forward. A body of nothing but open anchors therefore costs one
# cheap attempt per '<a' and finds nothing, exactly like a body of closed ones.
#
# The tag body deliberately excludes '<' as well. Allowing it (the old
# '[^>]*?) makes a body of nothing but '<a' quadratic again: measured on that
# body, per tag scan 0.016 s (<-excluded, this pattern) / 0.8 s (bound 512) /
# 6.2 s (bound 4096) for 256 KiB — a bound cannot buy back the unbounded look.
# Only a tag with a raw, unescaped '<' in an attribute (invalid HTML) is
# therefore no longer paired with its '</a>'; its href is still extracted and
# classified by _URL_RE, only the display text is dropped.
_ANCHOR_OPEN_RE = re.compile(r"<a\b[^<>]*?>", re.IGNORECASE)
# The attribute value is captured in all three spellings. A QUOTED value may
# contain whitespace on purpose: ``href=" javascript:..."`` is a working
# javascript link in every browser, but the old pattern excluded whitespace
# and therefore found no href at all (audit BUG-067). Whitespace inside the
# value is normalised away by ``_normalise_href`` before the scheme check.
_HREF_RE = re.compile(
    r"""href\s*=\s*(?:"(?P<quoted>[^"<>]*)"|'(?P<single>[^'<>]*)'|(?P<bare>[^<>"'\s>]+))""",
    re.IGNORECASE,
)
_ANCHOR_CLOSE_RE = re.compile(r"</a>", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]{0,4096}>")
_WS_RE = re.compile(r"[ \t\u00a0]+")
# Numeric HTML entities (&#104;, &#x68;) — the classic way to hide a scheme.
_NUMERIC_ENTITY_RE = re.compile(r"&#(?:x([0-9a-fA-F]{1,6})|(\d{1,7}));")
_NAMED_ENTITIES = {
    "&colon;": ":",
    "&sol;": "/",
    "&period;": ".",
    "&commat;": "@",
    "&equals;": "=",
    "&quest;": "?",
    "&amp;": "&",
    # Whitespace entities are the other half of BUG-067: a browser strips
    # them from the URL, so ``&#9;javascript:`` is a javascript link. The
    # numeric form is covered in ``_num`` below; these are the named spellings
    # HTML offers for the same characters.
    "&tab;": "\t",
    "&Tab;": "\t",
    "&newline;": "\n",
    "&NewLine;": "\n",
}

# Characters a URL parser removes/trims before looking at the scheme. WHATWG
# URL parsing (and every browser) removes ASCII tab/newline anywhere in the
# URL and strips C0 controls and spaces at both ends; ``urllib`` does neither.
_URL_TRIM_CHARS = "".join(chr(code) for code in range(0x21))


def _normalise_href(value: str) -> str:
    """Normalise an href the way a browser does before parsing it.

    ``" javascript:..."``, ``"\\tjavascript:..."`` and ``"&#9;javascript:..."``
    all execute in the client, but the scheme check saw the leading blank or
    the entity and found nothing (audit BUG-067). Tab/CR/LF are removed
    anywhere, all C0 controls and spaces at the ends — exactly the WHATWG
    rule, not a new one.
    """
    if not value:
        return ""
    for char in ("\t", "\r", "\n"):
        if char in value:
            value = value.replace(char, "")
    return value.strip(_URL_TRIM_CHARS)


def _href_value(tag: str) -> str:
    """The raw ``href`` attribute value of an anchor tag, or ``""``."""
    match = _HREF_RE.search(tag)
    if not match:
        return ""
    for group in ("quoted", "single", "bare"):
        value = match.group(group)
        if value is not None:
            return value
    return ""


def _unescape_entities(text: str) -> str:
    """Resolve numeric and common named HTML entities.

    Phishing kits encode the scheme (``&#104;ttp://``) or separators
    (``&colon;``) so a plain URL regex sees no link at all — the mail then
    looks link-free while the victim's browser renders a working link.
    Bounded to a single pass; never raises.
    """
    if "&" not in text:
        return text

    def _num(match: re.Match) -> str:
        try:
            code = int(match.group(1), 16) if match.group(1) else int(match.group(2))
        except (TypeError, ValueError):
            return match.group(0)
        # Only decode characters that appear in URLs; anything else is left
        # alone so we do not silently rewrite arbitrary text. Whitespace is
        # included because an entity-encoded tab/newline/space before the
        # scheme is invisible to a plain scan but removed by the browser.
        if 0x21 <= code <= 0x7E or code in (0x09, 0x0A, 0x0C, 0x0D, 0x20):
            return chr(code)
        return match.group(0)

    text = _NUMERIC_ENTITY_RE.sub(_num, text)
    for entity, char in _NAMED_ENTITIES.items():
        if entity in text:
            text = text.replace(entity, char)
    return text


_RECEIVED_RE = re.compile(r"^received:", re.IGNORECASE | re.MULTILINE)

# URI schemes that are dangerous in a mail body: they either execute code in
# the client (javascript/vbscript/data), reach the local disk (file/jar) or
# abuse a Windows protocol handler (ms-msdt, search-ms).
DANGEROUS_URI_SCHEMES = frozenset(
    {
        "javascript",
        "vbscript",
        "data",
        "file",
        "jar",
        "ms-msdt",
        "search-ms",
        "ms-officecmd",
        "smb",
        "mhtml",
        "cmd",
        "powershell",
    }
)
_DANGEROUS_URI_SCHEMES = DANGEROUS_URI_SCHEMES
# Hosts whose whole purpose is to conceal the real target.
_SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "adf.ly", "shorte.st", "cutt.ly", "rb.gy", "rebrand.ly", "s.id",
        "lnkd.in", "t.ly", "shorturl.at", "tiny.cc", "urlz.fr", "1drv.ms",
        "qrco.de", "qr.codes", "me-qr.com", "qrfy.io", "scan.me", "qr1.be",
        "q-r.to",
    }
)

# TLDs with a strongly elevated abuse ratio in phishing feeds.
_RISKY_TLDS = frozenset(
    {
        ".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
        ".click", ".link", ".work", ".loan", ".men", ".review", ".country",
        ".eat", ".rest", ".quest", ".buzz", ".cyou", ".sbs", ".cfd",
    }
)


def _decode_part(part: Message, limit: int) -> str:
    """Decode one part to text, bounded and never raising."""
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return ""
    if not isinstance(payload, bytes):
        return ""
    payload = payload[:limit]
    charset = part.get_content_charset() or "utf-8"
    for attempt in (charset, "utf-8", "latin-1"):
        try:
            return payload.decode(attempt, errors="replace")
        except (LookupError, UnicodeDecodeError, ValueError, TypeError):
            # ``ValueError`` is not a corner case: a header can name a codec
            # containing NUL (``charset="utf-8\x00"``), and codecs.lookup raises
            # ``ValueError: embedded null character`` — not LookupError. Fuzzing
            # found it (411-byte mail, regression input
            # tests/data/fuzz_regressions/eml-22255c198cedf229.bin); the header
            # is attacker-controlled, so "never raising" must include it.
            continue
    return payload.decode("latin-1", "replace")


def _decode_header_value(message: Message, name: str) -> str:
    try:
        value = message.get(name)
    except Exception:
        return ""
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _header_block_length(data: bytes) -> int:
    """Length of the RFC-822 header block: up to the first blank line.

    Measuring the LENGTH is uncapped on purpose: ``bytes.find`` is memchr-based
    and linear, and a shortened slice would lose the body separator. What is
    capped is the WORK done with the block — :data:`_MAX_HEADER_BLOCK_BYTES`
    bounds the decode/split/findall and the bytes handed to ``BytesParser``
    (audit SEC-034); the remainder of the body stays intact.
    """
    ends = [pos for pos in (data.find(b"\r\n\r\n"), data.find(b"\n\n")) if pos != -1]
    return min(ends) if ends else len(data)


# Eine Received-Zeile, so weit wie noetig zerlegt. ALLE Quantoren begrenzt:
# die Zeile ist angreiferkontrolliert, und `[\w.-]+` ist auf langer Eingabe
# quadratisch (siehe tests/test_regex_safety.py).
# Kopfzeilen, die ein fremdes Urteil behaupten. Bewusst kurz gehalten: jede
# weitere Zeile ist ein weiterer Angriffsweg, und die Aussage ist ohnehin
# dieselbe ("ein Filter fand das gut").
_FILTER_CLAIM_HEADERS = (
    "X-Spam-Status",
    "X-Spam-Score",
    "X-Spam-Flag",
    "X-Microsoft-Antispam",
    "X-Forefront-Antispam-Report",
    "X-Microsoft-Antispam-Mailbox-Delivery",
    "X-Proofpoint-Virus-Version",
    "X-Proofpoint-Spam-Details",
    "X-IronPort-AV",
    "X-Virus-Scanned",
)

_RX_FROM = re.compile(r"\bfrom\s+([\w.-]{1,255})", re.IGNORECASE)
_RX_BY = re.compile(r"\bby\s+([\w.-]{1,255})", re.IGNORECASE)
# RFC 5321 requires an IPv6 literal in a Received header to carry the
# ``IPv6:`` tag (``[IPv6:fd00::1]``). Without the optional tag the address was
# invisible: no private-IP and no blocklist check ran on it (audit BUG-070).
_RX_IP = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]{1,45})\]", re.IGNORECASE)
# "with" kommt zweimal vor: einmal als Protokoll ("with ESMTPS"), einmal im
# TLS-Zusatz ("(using TLSv1.2 with cipher AES256)"). Ohne den Ausschluss stand
# in der Anzeige "(cipher)" statt "(ESMTPS)".
_RX_WITH = re.compile(r"\bwith\s+(?!cipher\b)([A-Za-z0-9]{1,20})", re.IGNORECASE)
_RX_STAMP = re.compile(r";\s*([^;]{1,80})$")
# Die TLS-Angabe steht als Klammerzusatz: "(using TLSv1.2 with cipher AES256...)".
# Sie ist eine BEHAUPTUNG der Gegenstelle und ohne Netz nicht nachpruefbar.
_RX_TLS = re.compile(r"\(using\s+([A-Za-z0-9.]{1,20})\s+with\s+cipher\s+([\w-]{1,40})", re.IGNORECASE)


def _parse_received(raw: str) -> ReceivedHop:
    """Zerlegt eine ``Received:``-Zeile in ihre Station."""
    hop = ReceivedHop()
    match = _RX_FROM.search(raw)
    if match:
        hop.from_host = match.group(1)
    match = _RX_BY.search(raw)
    if match:
        hop.by_host = match.group(1)
    match = _RX_IP.search(raw)
    if match:
        hop.ip = match.group(1)
    match = _RX_WITH.search(raw)
    if match:
        hop.protocol = match.group(1)
    match = _RX_STAMP.search(raw.strip())
    if match:
        hop.stamp = match.group(1).strip()
    match = _RX_TLS.search(raw)
    if match:
        hop.tls = match.group(1)
    return hop


def _authserv_id(auth_results: str) -> str:
    """Der ausstellende Server aus ``Authentication-Results`` (oder leer)."""
    if not auth_results:
        return ""
    first = auth_results.split(";", 1)[0].strip()
    if not first or "=" in first:
        return ""
    match = re.fullmatch(r"[\w.-]{1,255}", first)
    return match.group(0) if match else ""


def _dkim_tag(header: str, tag: str) -> str:
    """Wert eines ``tag=`` aus einer ``DKIM-Signature`` (begrenzte Quantoren)."""
    if not header:
        return ""
    match = re.search(rf"(?:^|;)\s*{tag}\s*=\s*([^;]{{1,255}})", header)
    return match.group(1).strip() if match else ""


def _header_entries(raw_text: str, limit: int = _MAX_HEADER_LINES * 2):
    """Logische Kopfzeilen als ``(name_klein, wert)``, Faltung aufgeloest.

    NICHT per Zeile trennen: eine ``Received:``-Zeile ist nicht das Ende des
    Kopfblocks. Der erste Entwurf schnitt am naechsten ``Received:`` und zog
    damit alle folgenden Kopfzeilen in die Station hinein — der Zeitstempel
    der letzten Station war dann ``dmarc=pass`` aus der
    Authentication-Results-Zeile.

    Eine Kopfzeile beginnt bei einem Zeichen ohne Einrueckung; eingerueckte
    Folgezeilen (RFC 5322 Faltung) gehoeren zur vorigen.
    """
    entries: list[tuple[str, str]] = []
    name = ""
    value: list[str] = []
    for line in raw_text.splitlines():
        if not line.strip():
            break  # leerer Trenner: Ende des Kopfblocks
        if line[0] in " \t":
            if name:
                value.append(line.strip())
            continue
        if name:
            entries.append((name, " ".join(value)))
        head, _, rest = line.partition(":")
        name = head.strip().lower()
        value = [rest.strip()]
        if len(entries) >= limit:
            break
    if name and len(entries) < limit:
        entries.append((name, " ".join(value)))
    return entries


def parse_received_chain(raw_text: str, limit: int = 40) -> list[ReceivedHop]:
    """Alle ``Received:``-Stationen, neueste zuerst (wie im Kopf).

    ``limit`` begrenzt die Anzahl — eine Datei mit 100 000 gefaelschten
    Received-Zeilen soll nicht die Analyse bestimmen.
    """
    hops: list[ReceivedHop] = []
    for name, value in _header_entries(raw_text):
        if name != "received":
            continue
        hops.append(_parse_received(value))
        if len(hops) >= limit:
            break
    return hops


def _first_addr_spec(value: str) -> str:
    """The FIRST mailbox of a header value without angle brackets.

    RFC 5322 permits a mailbox-list (``a@b.de, c@d.de``) and group syntax
    (``Team: a@b.de;``) in every address header. Returning the whole value as
    the addr-spec made :func:`_domain_of` read ``d.de, c@d.de`` and produced
    four wrong findings for one correct header (BUG-071). The input is capped
    before ``getaddresses`` so the parser stays linear on attacker-sized
    headers; a value that yields no addr-spec falls back to the old behaviour.
    """
    probe = value.strip()
    if not probe:
        return ""
    if len(probe) > 4096:
        probe = probe[:4096]
    try:
        pairs = getaddresses([probe])
    except Exception:
        return ""
    for _display, addr in pairs:
        addr = addr.strip()
        if "@" in addr and not any(ch.isspace() for ch in addr):
            return addr
    return ""


def _split_address(value: str) -> tuple[str, str]:
    """Return ``(display_name, addr_spec)`` from a header value."""
    if not value:
        return "", ""
    # "Name" <a@b> / Name <a@b> / a@b
    #
    # No regex here. `<[^>]+>` was quadratic (80 000 '<' cost 28.28 s), and the
    # bounded form was only linear-BY-WINDOW: `[^>]{1,254}` tries up to 254
    # lengths at EVERY position, ~2.3 us/character — at MAX_READ_SIZE that is
    # minutes again. A single linear scan with quote state replaces both.
    #
    # ANFUEFRUNGSZEICHEN BEACHTEN. `<` und `>` duerfen INNERHALB eines
    # quoted-string stehen (RFC 5322), und genau das ist ein Umgehungsweg:
    #   From: "x <service@bank.tld>" <boese@evil.tld>
    # Der erste `<` liegt in den Anfuehrungszeichen, also wurde
    # `service@bank.tld` als Absender gelesen und der ECHTE `evil.tld`
    # verworfen. Gemessen: kein einziger Befund — Anzeigename, Marken- und
    # Domainpruefung liefen alle gegen die vom Angreifer behauptete Domain.
    # Massgeblich ist der erste `<`, der NICHT in Anfuehrungszeichen steht.
    # OHNE Anfuehrungszeichen im ganzen Wert gibt es nichts zu beachten, und
    # die direkte Schleife ist deutlich schneller als _find_unquoted (ein
    # Python-Aufruf je Position kostete auf 2 000 000 '<' gemessen 1,95 s statt
    # 0,75 s). Der Normalfall ist ein Header ohne Quotes.
    if '"' not in value:
        start = value.find("<")
        while start != -1:
            end = value.find(">", start + 1, start + 256)
            if end != -1 and 0 < end - start - 1 <= 254:
                return value[:start].strip(), value[start + 1 : end].strip()
            start = value.find("<", start + 1)
        addr = _first_addr_spec(value) if "<" not in value else ""
        return "", addr or value.strip()

    start = _find_unquoted(value, "<")
    while start != -1:
        end = _find_unquoted(value, ">", start + 1, start + 256)
        if end != -1 and 0 < end - start - 1 <= 254:
            display = value[:start].strip().strip('"').strip()
            return display, value[start + 1 : end].strip()
        start = _find_unquoted(value, "<", start + 1)
    addr = _first_addr_spec(value) if "<" not in value else ""
    return "", addr or value.strip()


def _find_unquoted(text: str, needle: str, start: int = 0, end: int | None = None) -> int:
    """Erstes Vorkommen von ``needle`` AUSSERHALB von Anfuehrungszeichen.

    Ein ``\"`` innerhalb eines quoted-string ist ein escaped quote und beendet
    ihn nicht. Lineare Suche mit Zustandsflag — kein Regex, aus demselben Grund
    wie oben.
    """
    limit = len(text) if end is None else min(end, len(text))
    index = start
    while index < limit:
        # BEIDE Suchen per str.find (memchr). Eine Zeichen-fuer-Zeichen-Schleife
        # in Python war hier 100x langsamer: 200 000 '<' kosteten 5,25 s und
        # 2 000 000 kosteten 52,7 s — dieselbe Quadratik, die `str.find` in der
        # Vorfassung vermieden hatte.
        hit = text.find(needle, index, limit)
        if hit == -1:
            return -1
        # Die Anfuehrungszeichen-Suche NUR bis zum Treffer. Mit `limit` statt
        # `hit` als Grenze scannte sie den ganzen Rest der Zeichenkette — bei
        # einer Folge aus 2 000 000 '<' also 2 000 000 mal den Rest, und das
        # war wieder quadratisch (gemessen 74,3 s).
        quote = text.find('"', index, hit)
        if quote == -1:
            return hit  # ausserhalb von Anfuehrungszeichen
        # Ueber den quoted-string springen. Ein \" beendet ihn nicht.
        close = quote + 1
        while True:
            close = text.find('"', close, limit)
            if close == -1:
                return -1  # offenes Anfuehrungszeichen: nichts mehr draussen
            backslashes = 0
            pos = close - 1
            while pos >= index and text[pos] == "\\":
                backslashes += 1
                pos -= 1
            if backslashes % 2 == 0:
                break
            close += 1
        index = close + 1
    return -1


def _strip_html(html: str) -> str:
    """Crude tag strip for text comparison (never rendered, never executed)."""
    text = _TAG_RE.sub(" ", html[:_MAX_HTML_STRIP_CHARS])
    text = (
        text.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
    )
    return _WS_RE.sub(" ", text).strip()


def parse_mail(data: bytes) -> MailFacts:
    """Parse an .eml into :class:`MailFacts` (bounded, never raises)."""
    facts = MailFacts()
    if not data:
        facts.parse_error = "Leere Datei"
        return facts
    # The parser's cost is quadratic in the multipart nesting depth, and this
    # is the second stage that parses the very same bytes as the attachment
    # extraction (``core.email_extract``) — bounding only one of the two
    # halves the cost instead of removing it. Both ask the same predicate;
    # see ``_MAX_MIME_LAYERS`` there for the measurement and the budget.
    #
    # A mail refused here is a diagnosis, not a second weighted statement:
    # the extraction path reports the same reason with weight 25
    # (EMAIL_PARSE_ERROR), this one reaches the panel with weight 0
    # (MAIL_PARSE_WARN) — one cause, one weighted statement.
    too_deep = mime_depth_note(data)
    if too_deep:
        facts.parse_error = too_deep
        return facts
    # Header block cap (audit SEC-034). The parser is handed at most
    # _MAX_HEADER_BLOCK_BYTES of headers; a synthetic separator keeps the rest
    # of the message (the body) exactly where it was. Without this the 20 MB
    # single header was materialised several times over by BytesParser,
    # splitlines and findall.
    header_block = _header_block_length(data)
    facts.header_truncated = header_block > _MAX_HEADER_BLOCK_BYTES
    parse_bytes = data
    if facts.header_truncated:
        # Skip the ORIGINAL separator: the synthetic one below replaces it, so
        # the body starts exactly where it did before.
        body_start = header_block
        if data[body_start : body_start + 4] == b"\r\n\r\n":
            body_start += 4
        elif data[body_start : body_start + 2] == b"\n\n":
            body_start += 2
        parse_bytes = (
            data[:_MAX_HEADER_BLOCK_BYTES] + b"\r\n\r\n" + data[body_start:]
        )
    try:
        message = BytesParser(policy=default_policy).parsebytes(parse_bytes)
    except Exception as exc:
        facts.parse_error = f"{type(exc).__name__}: {exc}"
        return facts

    facts.subject = _decode_header_value(message, "Subject")
    from_raw = _decode_header_value(message, "From")
    facts.from_display, facts.from_addr = _split_address(from_raw)
    facts.reply_to = _split_address(_decode_header_value(message, "Reply-To"))[1]
    facts.return_path = _split_address(_decode_header_value(message, "Return-Path"))[1]
    facts.to_addr = _split_address(_decode_header_value(message, "To"))[1]
    facts.message_id = _decode_header_value(message, "Message-ID")
    facts.auth_results = _decode_header_value(message, "Authentication-Results")
    facts.auth_verdicts = auth_verdicts(facts.auth_results)

    # The HEADER BLOCK, not the first 64 KiB: a long display name or a long
    # Authentication-Results line pushes the Received chain past that window,
    # and the mail then reports "keine Received-Kette" although it went through
    # a server. Measured: with 100 000 bytes of display name the padded mail
    # gained MAIL_NO_RECEIVED while the identical unpadded one did not.
    # Bounded by _MAX_HEADER_BLOCK_BYTES (SEC-034); the truncation is visible
    # in analyze_structure.
    raw_text = data[: min(header_block, _MAX_HEADER_BLOCK_BYTES)].decode(
        "latin-1", "replace"
    )
    facts.received_count = min(
        len(_RECEIVED_RE.findall(raw_text)), _MAX_HEADER_LINES
    )
    facts.received_hops = parse_received_chain(raw_text)
    # LISTEN-KOPFZEILEN (RFC 2919). GEMESSEN an 20 echten Ham-Mails aus
    # dem SpamAssassin-Korpus: 4 davon waren ROT, und zwar an Regeln, die
    # fuer eine Mailingliste den NORMALZUSTAND beschreiben —
    # MAIL_RETURN_PATH_MISMATCH (die "-admin@"-Adresse IST die
    # Bounce-Adresse der Liste, nicht der Autor), MAIL_DMARC_ALIGNMENT_FAIL
    # (Listen brechen die Ausrichtung per Design, weil sie die Mail neu
    # versenden) und MAIL_RECEIVED_PRIVATE_IP (der Listenserver relayt
    # intern weiter). Ohne diese Erkennung liest Malaz jede Listenmail als
    # Faelschung. List-Id ist der verlaessliche Marker; die uebrigen
    # decken aeltere Listen ab, die noch keine List-Id setzen.
    # LISTE NUR MIT BESTAETIGUNG, nicht auf eine Kopfzeile hin.
    #
    # "List-Id" allein ist unauthentifiziert: jeder Angreifer schreibt sie in
    # eine Phishing-Mail, und dann fielen MAIL_RETURN_PATH_MISMATCH (15) und
    # MAIL_DMARC_ALIGNMENT_FAIL (15) gratis weg — genau die BEC-Faelle, die
    # diese Regeln fangen sollen. Dasselbe Argument steht in diesem Modul
    # schon bei MAIL_AUTH_CLAIM_UNBACKED: eine Behauptung muss gedeckt sein.
    #
    # Bestaetigung heisst: der Envelope-Absender traegt die Bauart einer Liste
    # ("-admin@", "-bounces@", "-owner@", "-request@"). Das ist der zweite,
    # unabhaengige Hinweis, und beide zusammen sind schwer zu faelschen, ohne
    # dass die Regeln wieder greifen.
    _kopf = raw_text[:8192]
    _listen_kopf = any(
        f"\n{k}:" in _kopf.lower()
        # "mailing-list" ist die klassische Kopfzeile (Yahoo Groups, Mailman
        # aelterer Bauart). GEMESSEN: eine echte Yahoo-Groups-Mail trug
        # "Mailing-List:" und "X-Yahoo-…", aber KEINE List-Id — sie wurde
        # deshalb nicht als Liste erkannt und kam auf Score 80/RED.
        for k in ("list-id", "list-unsubscribe", "list-post", "list-help", "mailing-list")
    )
    # Ohne spitze Klammern: die Rueckkehradresse steht je nach Quelle als
    # "liste-admin@host" ODER als "<liste-admin@host>". GEMESSEN an 20 echten
    # Ham-Mails — mit der Klammer-Pflicht fiel die Erkennung von 14 auf 0.
    # "-return-" fehlte und ist der GRUND, warum die Erkennung auf echten
    # Listenarchiven versagte. GEMESSEN an 20 AKTUELLEN Mails aus dem
    # Apache-Archiv (httpd-users, 2025): 19 davon sind ROT, weil Mailman die
    # Rueckkehradresse als
    #   users-return-123584-archive-asf-public=cust-asf.ponee.io@httpd.apache.org
    # schreibt. Mein Muster kannte -admin@/-bounces@/-owner@/-request@, aber
    # nicht das Mailman-Schema — die Entschaerfung griff also nicht.
    #
    # Die 20 Ham-Mails von 2003 hatten diesen Fall nicht gezeigt: dort trugen
    # 6 von 8 Rueckkehradressen den Autorennamen, hier tragen 19 die
    # Listenmarke. Genau deshalb braucht eine Fp-Pruefung AKTUELLE Daten.
    _liste_rueckkehr = bool(
        re.search(
            # [^@\s]{0,64} statt [^@\s]*: unbeschraenkt laeuft das Muster bis
            # ans Ende der Zeichenkette, wenn kein "@" folgt — quadratisch.
            # Der Regex-Waechter der Suite hat es gefangen (test_regex_safety).
            # Die Marke steht HINTER einem Bindestrich, nicht zwingend direkt
            # vor dem "@". Mailman schreibt "users-return-123584-…@host", das
            # Muster "-return-@" trifft dort nie. Gemessen an 20 aktuellen
            # Apache-Mails: 19 ROT, weil genau das nicht passte.
            r"(^|[<\s])[^@\s]{0,64}"
            r"-(admin|bounces|owner|request|leave|subscribe|return|unsubscribe)[-@.]",
            facts.return_path or "",
            re.I,
        )
    )
    # Zweiter Hinweis: die Rueckkehradresse gehoert zur LISTEN-Infrastruktur.
    #
    # GEMESSEN an einer echten Yahoo-Groups-Mail: die Rueckkehradresse lautet
    # "sentto-12345-6789-absender=domain@returns.groups.yahoo.com" — sie
    # traegt KEIN "-admin@"/"-bounces@"/"-return-", das Muster greift dort
    # also nicht. Die Domain ist dafuer eindeutig: sie gehoert dem
    # Listendienst, nicht dem Absender.
    _listen_domain = any(
        d in (facts.return_path or "").lower()
        for d in ("@returns.groups.yahoo.com", "@yahoogroups.com", "@googlegroups.com")
    )
    facts.is_mailing_list = _listen_kopf and (_liste_rueckkehr or _listen_domain)
    # Welcher Server will die Authentifizierung bescheinigt haben?
    #
    # RFC 8601 verlangt einen authserv-id VOR dem ersten Semikolon. Fehlt er
    # ("Authentication-Results: spf=fail; ..."), dann faengt der erste Token
    # bereits ein "method=result" an — ihn als Servernamen zu lesen meldete
    # "behauptet durch 'spf'", was kein Satz ist. Ohne Namen gibt es niemanden,
    # den man gegen die Kette halten koennte, also bleibt das Feld leer.
    facts.auth_claimed_by = _authserv_id(facts.auth_results)
    # DKIM-Auszeichnung: die signierende Domain (d=) ist die einzige Angabe in
    # der Mail, mit der sich die Absenderdomain unabhaengig vergleichen laesst.
    dkim = _decode_header_value(message, "DKIM-Signature")
    facts.dkim_domain = _dkim_tag(dkim, "d")
    facts.dkim_selector = _dkim_tag(dkim, "s")
    facts.date_header = _decode_header_value(message, "Date")
    for header in _FILTER_CLAIM_HEADERS:
        value = _decode_header_value(message, header)
        if value.strip():
            facts.filter_claims[header] = value.strip()[:300]

    text_parts: list[str] = []
    html_parts: list[str] = []
    budget = _MAX_BODY_BYTES
    # Iterative walk: a deeply nested multipart mail must not recurse.
    #
    # ``herkunft`` ist der Name der angehaengten Mail, in der wir gerade
    # stecken — leer ausserhalb einer solchen. Ohne diese Spur waere der Text
    # aus einer angehaengten .eml von dem der aeusseren Mail nicht zu
    # unterscheiden; der Nutzer saehe fremden Inhalt als Mailtext.
    stack: list[tuple[Message, str]] = [(message, "")]
    seen = 0
    while stack and budget > 0 and seen < config.MAIL_MAX_MIME_PARTS:
        part, herkunft = stack.pop()
        seen += 1
        # Der Name wird VOR dem Multipart-Zweig gelesen. Vorher stand er
        # danach: eine angehaengte .eml (message/rfc822) ist multipart, wurde
        # also weiter gereicht und bekam nie einen Namen — sie fehlte in
        # ``attachment_names`` vollstaendig.
        try:
            filename = part.get_filename()
        except Exception:
            filename = None
        if filename:
            facts.attachment_names.append(Path(filename).name)
        try:
            if part.is_multipart():
                subparts = list(part.get_payload())
                ctype = (part.get_content_type() or "").lower()
                # Eine MITGESENDETE Mail mit Dateinamen ist ein ANHANG: sie
                # bekommt in core/email_extract ein EIGENES Scan-Ergebnis
                # (eigene Links, eigener Abgleich, eigenes Urteil). Ihr Text
                # gehoert dorthin — stuende er zusaetzlich hier, meldete ein
                # und dieselbe URL zweimal, einmal am Kind und einmal am
                # Elternteil.
                #
                # OHNE Dateinamen ist sie kein Anhang und bekommt in
                # core/email_extract KEIN eigenes Ergebnis; dann bleibt ihr
                # Text hier. Er muss aber GEKENNZEICHNET bleiben — sonst
                # liest der Nutzer fremden Inhalt als Text der geoeffneten
                # Mail, und das ist genau die Taeuschung, die diese Aenderung
                # schliesst.
                #
                # GEMESSEN: ``herkunft`` wurde nie gesetzt (Startwert "" und
                # unveraendert weitergereicht), die Kennzeichnung unten war
                # damit toter Code — der unbenannte Fall lief unmarkiert durch.
                if ctype == "message/rfc822":
                    if filename:
                        continue
                    tiefer = "ohne Dateinamen"
                else:
                    tiefer = herkunft
                stack.extend((teil, tiefer) for teil in reversed(subparts))
                continue
        except Exception:
            continue
        ctype = (part.get_content_type() or "").lower()
        if ctype not in ("text/plain", "text/html"):
            continue
        if budget <= 0:
            if ctype == "text/html":
                facts.html_body_truncated = True
            continue
        raw_html_len = 0
        if ctype == "text/html":
            try:
                _rp = part.get_payload(decode=True)
                raw_html_len = len(_rp) if isinstance(_rp, bytes) else 0
            except Exception:
                raw_html_len = 0
        decoded = _decode_part(part, budget)
        if ctype == "text/html" and raw_html_len > budget:
            facts.html_body_truncated = True
        if not decoded:
            continue
        budget -= len(decoded)
        if herkunft:
            decoded = f"[Inhalt der angehängten E-Mail: {herkunft}]\n{decoded}"
        if ctype == "text/html":
            html_parts.append(decoded)
        else:
            text_parts.append(decoded)

    # BUG-065: the walk used to stop at 1600 nodes without any statement,
    # while email_extract accepted 4096 parts — a payload behind 1600 padding
    # parts scored GREEN 0. The shared budget now ends at the same number;
    # what remains on the stack is explicitly "not inspected".
    if stack and seen >= config.MAIL_MAX_MIME_PARTS:
        facts.parts_truncated = True

    facts.text_body = "\n".join(text_parts)[:_MAX_BODY_BYTES]
    joined_html = "\n".join(html_parts)
    if len(joined_html) > _MAX_BODY_BYTES:
        facts.html_body_truncated = True
    facts.html_body = joined_html[:_MAX_BODY_BYTES]
    facts.links = extract_links(facts.text_body, facts.html_body)
    return facts


# --------------------------------------------------------------------------- #
# Link extraction and static checks
# --------------------------------------------------------------------------- #


def _host_of(url: str) -> tuple[str, str]:
    # Browsers treat "\" exactly like "/" in the authority of a special
    # scheme; ``urlsplit`` does not. ``https://evil.example\@good.example``
    # therefore visits evil.example in a browser, while urlsplit reports
    # good.example as the host — the display-text mismatch check then stayed
    # silent (audit SEC-035). Normalise before parsing.
    if "\\" in url:
        url = url.replace("\\", "/")
    try:
        split = urlsplit(url)
    except Exception:
        return "", ""
    host = (split.hostname or "").lower()
    return split.scheme.lower(), host


def _is_ip_literal(host: str) -> bool:
    """Is ``host`` an IPv4/IPv6 literal, not a domain name?

    ``urlsplit().hostname`` returns IPv6 WITHOUT the square brackets, so the
    old ``host.startswith("[")`` branch was dead code: ``http://[2001:db8::1]``
    reported ``is_ip_literal=False`` and the IP-literal finding never fired
    (BUG-073). The bare check also accepted impossible addresses such as
    ``999.1.1.1``; the octets are range-checked now.
    """
    if not host:
        return False
    value = host.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if ":" in value:
        # Scoped IPv6 ("fe80::1%eth0") is still a literal; validate the
        # address part, not the zone name.
        address = value.split("%", 1)[0]
        try:
            ipaddress.IPv6Address(address)
        except ValueError:
            return False
        return True
    parts = value.split(".")
    return len(parts) == 4 and all(
        # ``isdigit()`` alone accepts superscripts/other Unicode digits, and
        # ``int("²")`` raises ValueError — an attacker-controlled hostname
        # must never crash the classifier.
        part.isascii() and part.isdigit() and int(part) <= 255
        for part in parts
    )


def _has_risky_tld(host: str) -> bool:
    """Does ``host`` end in one of the flagged TLDs?

    Every entry carries its leading dot, so a lookup can never match a mere
    label suffix: the old ``"eat"`` entry flagged ``intranet-cheat`` while
    ``x.eat`` (the intended match) was never a suffix of itself (BUG-074).
    A trailing dot is the same FQDN and is normalised away first.
    """
    if not host:
        return False
    value = host.rstrip(".")
    return any(value.endswith(tld) for tld in _RISKY_TLDS)


def _strip_www(host: str) -> str:
    """Drop a leading ``www.`` label (never a character set).

    ``str.strip("www.")`` would remove every leading/trailing w/. character —
    "www.web.de" became "eb.de", a real bug flagged by the linter.
    """
    return host[4:] if host.startswith("www.") else host


def _display_host(display: str) -> str:
    """Extract the host a display text *claims* to point at.

    Handles both forms users see: a full URL and a bare host with path
    ("www.shop.de/angebot"). The path part must be dropped — comparing the
    full string against the href's host would flag every legitimate link
    whose text includes a path (a real false positive found in testing).
    """
    m = _URL_RE.search(display)
    if m:
        _scheme, host = _host_of(m.group(0))
        return host
    text = display.strip()
    if " " in text or "." not in text:
        return ""
    text = text.strip("/")
    # Strip userinfo/port/path: "user@host:8080/pfad" -> host.
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0]
    if ":" in text:
        text = text.rsplit(":", 1)[0]
    return text.lower()


_BARE_WWW_RE = re.compile(
    r"^www\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,}|xn--[a-z0-9-]+)"
    r"(?::\d{1,5})?(?:[/?#].*)?$",
    re.IGNORECASE,
)
_URL_BORDER_STRIP = (
    " \t\r\n\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\ufeff\u061c\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
    "\u2066\u2067\u2068\u2069"
)


def _canonicalize_idna_url(url: str) -> tuple[str, str, str, bool]:
    """Return ``(canonical_url, scheme, ascii_host, is_idn)`` with ASCII netloc host."""
    norm = url.replace("\\", "/") if "\\" in url else url
    try:
        parts = urlsplit(norm)
    except Exception:
        return url, "", "", False
    scheme = parts.scheme.lower()
    raw_host = (parts.hostname or "").lower()
    if not raw_host:
        return url, scheme, "", False
    is_idn = False
    ascii_host = raw_host
    if not raw_host.isascii():
        is_idn = True
        try:
            ascii_host = raw_host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            ascii_host = raw_host
    netloc = parts.netloc
    if netloc and ascii_host != raw_host:
        # Replace ONLY the parsed host portion of netloc (preserve userinfo@ and :port).
        userinfo, sep, hostport = netloc.rpartition("@")
        if not sep:
            userinfo = ""
        port_part = ""
        host_part = hostport
        if hostport.startswith("["):
            end_b = hostport.find("]")
            if end_b != -1:
                host_part = hostport[: end_b + 1]
                port_part = hostport[end_b + 1 :]
        elif ":" in hostport:
            host_part, port_num = hostport.rsplit(":", 1)
            port_part = ":" + port_num
        _ = host_part
        new_netloc = f"{userinfo}{sep}{ascii_host}{port_part}"
        canonical = parts._replace(scheme=scheme, netloc=new_netloc).geturl()
    elif parts.scheme and parts.scheme != scheme:
        canonical = parts._replace(scheme=scheme).geturl()
    else:
        canonical = norm
    return canonical, scheme, ascii_host, is_idn


def classify_url(url: str, display: str = "", *, canonicalize: bool = True) -> LinkFacts | None:
    """Classify one URL (shared by EML link extraction and QR-code analysis).

    Handles uppercase schemes (``HTTPS://...``), scheme-less hosts
    (``//host/path``, ``host.tld/path``, ``www.host.tld``), and raw UTF-8 IDNs
    (normalising the netloc host via IDNA to Punycode ASCII).
    """
    cleaned = url.strip(_URL_BORDER_STRIP).rstrip(".,;!?)")
    if not cleaned:
        return None
    candidate = cleaned
    if canonicalize:
        low = candidate.lower()
        if low.startswith("//"):
            candidate = "https:" + candidate
        elif not low.startswith(("http://", "https://")) and (
            _SCHEMELESS_HREF_RE.match(candidate) or _BARE_WWW_RE.match(candidate)
        ):
            candidate = "https://" + candidate
    canonical, scheme, host, is_idn = _canonicalize_idna_url(candidate)
    if not scheme and ":" in candidate:
        scheme = candidate.split(":", 1)[0].lower()
    if canonicalize and not host and scheme not in DANGEROUS_URI_SCHEMES:
        return None
    link = LinkFacts(
        url=canonical if canonicalize else cleaned,
        display_text=display.strip(),
        host=host,
        scheme=scheme,
    )
    link.is_ip_literal = _is_ip_literal(host)
    link.is_punycode = ("xn--" in host) or is_idn
    link.is_shortener = host in _SHORTENERS
    link.risky_tld = _has_risky_tld(host)
    try:
        link.has_credentials = "@" in (urlsplit(candidate.replace("\\", "/")).netloc or "")
    except Exception:
        link.has_credentials = False
    if display and host:
        disp_host = _display_host(display)
        if disp_host and _strip_www(disp_host) != _strip_www(host):
            link.mismatch = True
    return link


def _add_link(out: list[LinkFacts], seen: set[str], url: str, display: str) -> None:
    """Classify one URL and append it to ``out`` (shared by both extractors)."""
    cleaned = url.strip().rstrip(".,;!?)")
    if not cleaned or len(out) >= _MAX_LINKS or cleaned in seen:
        return
    seen.add(cleaned)
    link = classify_url(cleaned, display, canonicalize=False)
    if link is not None:
        out.append(link)


def _web_href_target(href: str) -> str:
    """The http(s) URL an anchor resolves to, or "" if it is not one.

    A mail client resolves ``//host/pfad`` and ``host/pfad`` against the
    document, so both reach exactly the host the absolute form reaches. The
    old gate accepted only the two literal ``http://``/``https://`` prefixes,
    which made the scheme a free way out of every link classification:
    dropping ``http:`` from a phishing href removed the display-text mismatch
    (30), the IP-literal, punycode and shortener checks with it — measured on
    two otherwise byte-identical mails as 55 ROT against 25 GELB.

    What stays out is the other direction of the same table: relative paths
    (``images/logo.png``, ``./x``, ``../x``), fragments (``#top``), bare file
    names (``rechnung.pdf``) and every non-web scheme (``mailto:``, ``tel:``,
    ``javascript:`` …) name no foreign host, so there is nothing to classify.
    ``javascript:``/``data:``/``file:`` keep their own finding below.
    """
    lowered = href.lower()
    if lowered.startswith(("http://", "https://")):
        return href
    if href.startswith("//"):
        resolved = "http:" + href
    elif _SCHEMELESS_HREF_RE.match(href):
        resolved = "http://" + href
    else:
        return ""
    # "//" with nothing behind it resolves to no host at all.
    return resolved if _host_of(resolved)[1] else ""


def _iter_anchors(html: str) -> Iterator[tuple[str, str]]:
    """Yield ``(href, text)`` for every anchored link in ``html``.

    Pairs exactly like the ``finditer`` over the old single pattern did: the
    text runs from the open tag to the *next* ``</a>``, so an unclosed ``<a>``
    yields nothing (its URL is still picked up by ``_URL_RE``), a nested ``<a>``
    inside an open anchor's text is swallowed with it, and scanning resumes
    behind each pair's ``</a>``.

    The closing tags are indexed once up front, which is what keeps the lookup
    per anchor a bisect. Scanning forward for each anchor instead was the
    quadratic term — see ``_ANCHOR_OPEN_RE``.
    """
    close_positions = [match.start() for match in _ANCHOR_CLOSE_RE.finditer(html)]
    if not close_positions:
        return
    resume = 0
    for tag in _ANCHOR_OPEN_RE.finditer(html):
        if tag.start() < resume:
            continue  # inside the text of an already emitted pair
        href = _href_value(tag.group(0))
        if not href:
            continue
        index = bisect_left(close_positions, tag.end())
        if index == len(close_positions):
            continue  # no closing tag anywhere behind this one
        close = close_positions[index]
        resume = close + len("</a>")
        yield href, html[tag.end():close]


def extract_links(text_body: str, html_body: str) -> list[LinkFacts]:
    """Collect and statically classify every URL in the mail body."""
    out: list[LinkFacts] = []
    seen: set[str] = set()

    if html_body:
        for href_raw, text_raw in _iter_anchors(html_body):
            # HTML entities hide the scheme from a plain scan: phishing kits
            # write href="&#104;ttp://…" so a naive extractor sees nothing.
            # _unescape_entities runs FIRST so the URL is classified properly;
            # _normalise_href then removes the whitespace a browser removes
            # (``" javascript:``/``&#9;javascript:``) before the scheme check.
            href = _normalise_href(_unescape_entities(href_raw))
            link_text = _unescape_entities(_strip_html(text_raw))
            target = _web_href_target(href)
            if target:
                _add_link(out, seen, target, link_text)
            elif href:
                # Non-web schemes are not extracted as URLs (they are not
                # links we can classify) but must never pass silently:
                # javascript:/data:/vbscript: execute in the client,
                # file:// reaches the local disk. Record them as findings.
                scheme = href.split(":", 1)[0].lower() if ":" in href else ""
                if scheme in _DANGEROUS_URI_SCHEMES:
                    _add_link(out, seen, f"{scheme}:...", link_text)
            if len(out) >= _MAX_LINKS:
                break
    for source in (text_body, html_body):
        if not source or len(out) >= _MAX_LINKS:
            continue
        for match in _URL_RE.finditer(_unescape_entities(source)):
            _add_link(out, seen, unquote(match.group(0)), "")
    return out


# Every mechanism a receiving server can report on. The verdict is read from
# the mail's own Authentication-Results header: Malaz is offline and cannot
# compute SPF/DKIM/DMARC itself (that needs the receiving server's context and
# DNS), so what can be said is what the header says — and, just as important,
# what it does NOT say.
_AUTH_MECHANISMS = ("spf", "dkim", "dmarc")
_AUTH_FAIL_WORDS = ("fail", "softfail", "permerror", "temperror", "policy")
_AUTH_PASS_WORDS = ("pass", "bestguesspass")


def auth_verdicts(auth_results: str) -> dict[str, str]:
    """``{mechanism: verdict}`` from an ``Authentication-Results`` header.

    ``pass`` / ``fail`` come from the header. ``none`` means the header exists
    but says nothing about that mechanism; ``unknown`` means there is no header
    at all — in which case nothing about the sender's authentication can be
    judged, and the viewer has to say that instead of staying silent.
    """
    text = (auth_results or "").lower()
    if not text.strip():
        return {mech: "unknown" for mech in _AUTH_MECHANISMS}
    out: dict[str, str] = {}
    for mech in _AUTH_MECHANISMS:
        found = re.findall(rf"\b{mech}\s*=\s*([a-z]+)", text)
        if not found:
            out[mech] = "none"
        elif any(v in _AUTH_FAIL_WORDS for v in found):
            out[mech] = "fail"
        elif any(v in _AUTH_PASS_WORDS for v in found):
            out[mech] = "pass"
        else:
            out[mech] = "none"
    return out
