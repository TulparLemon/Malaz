"""Static .eml analysis: headers, body text, and links (no execution).

Malaz analyses mail statically and offline; nothing in this module executes,
fetches, or renders anything. It answers three questions for a dropped .eml:

1. **Structure** — do the headers hang together? Display-name vs. address,
   ``Reply-To``/``Return-Path`` mismatches, ``Received`` chain sanity, and the
   authentication results the receiving server already recorded
   (SPF/DKIM/DMARC in ``Authentication-Results``).
2. **Body text** — does the text "make sense"? HTML/text divergence, hidden
   text, obfuscation, paid-lure and urgency phrasing (DE+EN), encoding damage.
3. **Links** — display text vs. real target, punycode/homoglyph tricks, IP
   literals, shorteners, risky TLDs, and (opt-in only) a reputation lookup
   based on the URL hash. The URL itself is never opened.

Design notes
------------
* Everything is bounded: header count, body size, link count, regex work.
* The body is decoded from the MIME structure (base64/QP), not from raw
  bytes — otherwise every encoded mail would look like noise.
* ``policy.default`` tolerates the broken mails that real phishing uses.
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
from .domain_blocklist import is_blocked_domain, load_domain_blocklist_or_error
from .email_extract import mime_depth_note
from .ipblocklist import is_blocked_ip, load_ip_blocklist_or_error
from .risky_types import RISKY_SUFFIXES

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
_DANGEROUS_URI_SCHEMES = frozenset(
    {
        "javascript",
        "vbscript",
        "data",
        "file",
        "jar",
        "ms-msdt",
        "search-ms",
        "ms-officecmd",
    }
)
# Hosts whose whole purpose is to conceal the real target.
_SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "adf.ly", "shorte.st", "cutt.ly", "rb.gy", "rebrand.ly", "s.id",
        "lnkd.in", "t.ly", "shorturl.at", "tiny.cc", "urlz.fr", "1drv.ms",
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

# Well-known brands that phishing kits impersonate in the display name.
_IMPERSONATED_BRANDS = (
    "microsoft", "windows", "office365", "outlook", "apple", "icloud", "paypal",
    "amazon", "dhl", "dpd", "hermes", "fedex", "ups", "post", "sparkasse",
    "volksbank", "commerzbank", "deutsche bank", "ing-diba",
    "netflix", "spotify", "telekom", "vodafone", "1&1", "rewe", "lidl", "aldi",
    "google", "facebook", "instagram", "whatsapp", "binance", "coinbase",
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


# Die Adresse in einem Anzeigenamen. EINE Definition fuer das ganze Paket:
# das Muster stand wortgleich in eml_analysis UND mail_view, und beim
# ReDoS-Fix wurde zuerst nur eine Stelle repariert — die andere lief weiter
# quadratisch (276,5 s auf 200 000 Zeichen). scripts/check_duplicate_logic.py
# haelt das jetzt fest.
#
# Die Quantoren sind BEGRENZT (RFC 5321: 64 fuer den lokalen Teil, 255 fuer die
# Domain). Unbeschraenkt ist die Form quadratisch auf angreiferkontrolliertem
# Text: die Klasse startet an jeder Position und laeuft bis ans Ende.
ADDRESS_IN_DISPLAY_RE = r"[\w.+-]{1,64}@([\w.-]{1,255}\.[a-z]{2,})"
DOMAIN_IN_ADDRESS_RE = r"@([\w.-]{1,255}\.[a-z]{2,})"


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

# Ein Servername in einer Filterkopfzeile ("by mx.firma.de at ...").
_RX_FILTER_SERVER = re.compile(
    r"\b(?:by|at|from)\s+([\w.-]{1,255}\.[a-z]{2,})", re.IGNORECASE
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


# Ab dieser Luecke zwischen Date-Kopf und erster Zustellung wird berichtet.
# Grosszuegig: Zeitzonenfehler und Warteschlangen kommen vor, ein echter
# Zustellweg liegt im Bereich von Sekunden bis Minuten.
_MAX_DELIVERY_GAP_SECONDS = 12 * 3600

# Transportversionen, die als veraltet gelten. Rein informativ.
_WEAK_TLS = {"tlsv1", "tlsv1.0", "tlsv1.1", "sslv2", "sslv3"}


# Ein Bild von 1x1 ist ein Zaehlpixel: es sagt dem Absender, dass die Mail
# geoeffnet wurde. Gebraucht von analyze_body — der EINEN Stelle, die den
# HTML-Rumpf prueft.
_RX_TRACKING_PIXEL = re.compile(
    r"<img[^>]{0,400}?(?:width\s*=\s*[\x22']?1[\x22']?[^>]{0,200}?height\s*=\s*[\x22']?1[\x22']?"
    r"|height\s*=\s*[\x22']?1[\x22']?[^>]{0,200}?width\s*=\s*[\x22']?1[\x22']?)",
    re.IGNORECASE,
)


def _message_id_domain(value: str) -> str:
    """Domain aus ``<id@domain>`` — leer, wenn keine enthalten ist."""
    text = (value or "").strip().strip("<>").strip()
    if "@" not in text:
        return ""
    domain = text.rsplit("@", 1)[1].strip().strip(">").strip()
    return domain if "." in domain else ""


def _parse_mail_date(value: str):
    """Datum aus einer Kopfzeile, oder ``None`` wenn es nicht lesbar ist."""
    from email.utils import parsedate_to_datetime

    try:
        parsed = parsedate_to_datetime((value or "").strip())
    except (TypeError, ValueError):
        return None
    if parsed is None or parsed.tzinfo is None:
        return None
    return parsed


def _is_private_ip(value: str) -> bool:
    """Private, Loopback- oder Link-Local-Adresse (IPv4 und IPv6)."""
    text = (value or "").strip().strip("[]").lower()
    if not text:
        return False
    if ":" in text:
        # IPv6: Loopback ::1, Link-Local fe80::/10, Unique Local fc00::/7
        return text in ("::1", "::") or text.startswith(("fe80:", "fc", "fd"))
    parts = text.split(".")
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return False
    octets = [int(part) for part in parts]
    if any(o > 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    return (
        a == 10
        or a == 127
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or (a == 169 and b == 254)
        or a == 0
    )


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


# KURZE Phrasen brauchen Wortgrenzen, lange duerfen im Wort stecken.
#
# GEMESSEN auf 20 echten Ham-Mails (SpamAssassin-Korpus): "tan" traf als
# blosser Teilstring in "understanding", "inheritance", "standing" und
# "instance" — vier von zwanzig sauberen Mails galten damit als
# "Zugangsdaten-Ansprache" (MAIL_BODY_CREDENTIALS, 15 Punkte). "pin" hat
# dieselbe Form ("spin", "opinion", "Pinguin").
#
# Umgekehrt MUESSEN lange Phrasen Teilstring bleiben: das Deutsche bildet
# Komposita, und "Kreditkartennummer" oder "Passwortabfrage" enthalten die
# Phrase, ohne sie als eigenes Wort zu fuehren. Gemessen: eine Wortgrenze
# fuer "kreditkarte" liesse die Kreditkartennummer durchfallen.
#
# Deshalb die Laengengrenze: bis vier Zeichen als eigenes Wort, darueber als
# Teilstring. Sie ist keine runde Zahl, sondern die Grenze, unter der Woerter
# in anderen Woertern vorkommen.
_WORTGRENZE_AB = 5


def _phrase_trifft(phrase: str, lowered: str) -> bool:
    """Steht die Phrase im Text — kurz nur als Wort, lang auch im Wort?"""
    if len(phrase) >= _WORTGRENZE_AB:
        return phrase in lowered
    # Kein \b: das kennt keine Umlaute. Die Zeichenklasse tut es.
    return (
        re.search(
            r"(?<![a-z\u00e4\u00f6\u00fc\u00df0-9])" + re.escape(phrase)
            + r"(?![a-z\u00e4\u00f6\u00fc\u00df0-9])",
            lowered,
        )
        is not None
    )


# Steht im Detailtext, wenn die Mail von einer Liste kommt — der Leser soll
# den Grund sehen und nicht raten muessen, warum der Befund harmlos bleibt.
_LISTEN_HINWEIS = (
    " — bei einer MAILINGLISTE ist das der Normalfall: die Bounce-Adresse "
    "gehoert der Liste, nicht dem Autor"
)


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
        decoded = _decode_part(part, budget)
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
    facts.html_body = "\n".join(html_parts)[:_MAX_BODY_BYTES]
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


def _add_link(out: list[LinkFacts], seen: set[str], url: str, display: str) -> None:
    """Classify one URL and append it to ``out`` (shared by both extractors)."""
    url = url.strip().rstrip(".,;!?)")
    # NOT ":" — a placeholder like "javascript:..." carries the scheme only
    # in its colon; stripping it made the scheme check miss entirely
    # (audit finding caught by the dangerous-scheme test).
    if not url or len(out) >= _MAX_LINKS or url in seen:
        return
    seen.add(url)
    scheme, host = _host_of(url)
    if not scheme and ":" in url:
        # urlsplit() reports no scheme for placeholders like "javascript:..."
        # (no "//"). Read it directly so the dangerous-scheme check works.
        scheme = url.split(":", 1)[0].lower()
    link = LinkFacts(url=url, display_text=display.strip(), host=host, scheme=scheme)
    link.is_ip_literal = _is_ip_literal(host)
    link.is_punycode = "xn--" in host
    link.is_shortener = host in _SHORTENERS
    link.risky_tld = _has_risky_tld(host)
    try:
        # Same normalisation as ``_host_of``: a backslash before the "@" is a
        # path separator for the browser, not userinfo (SEC-035).
        link.has_credentials = "@" in (urlsplit(url.replace("\\", "/")).netloc or "")
    except Exception:
        link.has_credentials = False
    if display and host:
        disp_host = _display_host(display)
        # Only a genuinely different host is a mismatch — a path, a "www."
        # prefix or a trailing slash must not trigger it.
        if disp_host and _strip_www(disp_host) != _strip_www(host):
            link.mismatch = True
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


# --------------------------------------------------------------------------- #
# Body heuristics
# --------------------------------------------------------------------------- #

# Urgency / payment / credential lures (DE + EN). Deliberately phrase-based:
# single words like "Konto" alone are far too common in legitimate mail.
_LURE_PHRASES = (
    # English
    "verify your account", "confirm your identity", "your account will be",
    "account has been suspended", "unusual sign-in", "unusual activity",
    "click here to update", "update your payment", "payment failed",
    "wire transfer", "bank transfer", "gift card", "itunes card",
    "you have won", "claim your prize", "act now", "urgent action",
    "within 24 hours", "final notice", "avoid suspension",
    # German
    "konto überprüfen", "konto bestätigen", "konto wurde gesperrt",
    "ihr konto wird", "zahlung fehlgeschlagen", "zahlungsdaten aktualisieren",
    "dringend handeln", "letzte mahnung", "innerhalb von 24 stunden",
    "bitte bestätigen sie", "zur verifizierung", "gutschein", "gewonnen",
    "paket konnte nicht zugestellt", "sendung konnte nicht",
    "rechnung offen", "mahnung", "sofort bezahlen",
)

# Credential-harvesting wording that only makes sense in a phishing flow.
_CREDENTIAL_PHRASES = (
    "passwort", "password", "kennwort", "pin", "tan", "einmalpasswort",
    "kreditkarte", "credit card", "cvv", "iban", "sozialversicherungsnummer",
    "social security", "login", "anmelden", "zugangsdaten",
)

# Attachment names that are dangerous when merely opened.
# Die Endungen stehen in core/risky_types.py — EINE Quelle. GEMESSEN: diese
# Liste und die PDF-Fassung waren bereits auseinandergelaufen (".hwp" fehlte
# dort, ".sh/.py/.apk" hier).
_RISKY_ATTACHMENT_SUFFIXES = RISKY_SUFFIXES

# Double extensions that hide the real type (invoice.pdf.exe).
_DOUBLE_EXT_RE = re.compile(
    r"\.[a-z0-9]{2,4}\.(exe|scr|bat|cmd|js|jse|vbs|vbe|wsf|ps1|hta|lnk|jar|iso|img)$",
    re.IGNORECASE,
)


@dataclass
class BodyReport:
    """Outcome of the body-text heuristics."""

    readable: bool = True
    looks_meaningful: bool = True
    lure_hits: tuple[str, ...] = ()
    credential_hits: tuple[str, ...] = ()
    html_text_divergence: float = 0.0
    hidden_text: bool = False
    # Ein 1x1-Bild ist ein Zaehlpixel, KEIN versteckter Text - eigener Befund
    # mit eigenem Gewicht (siehe eml_pipeline). Es steckt in fast jeder
    # legitimen HTML-Werbe-Mail.
    tracking_pixel: bool = False
    notes: tuple[str, ...] = ()


def _ratio_of_control_chars(text: str) -> float:
    if not text:
        return 0.0
    bad = sum(1 for ch in text if ch == "\ufffd" or (ord(ch) < 0x20 and ch not in "\r\n\t"))
    return bad / len(text)


def analyze_body(facts: MailFacts) -> BodyReport:
    """Answer "does this text make sense?" with deterministic local checks.

    ``looks_meaningful`` is deliberately conservative: it flips to False only
    for text that is plainly broken (encoding garbage, no words at all), not
    for merely suspicious phrasing — that is what the hit lists are for.
    """
    report = BodyReport()
    text = (facts.text_body or "").strip()
    html = facts.html_body or ""

    # Encoding damage: replacement chars and stray control bytes.
    ratio = _ratio_of_control_chars(text)
    if ratio > 0.10:
        report.readable = False
        report.notes += (f"Text stark beschädigt ({ratio:.0%} unlesbare Zeichen)",)

    words = re.findall(r"[A-Za-zÄÖÜäöüß]{3,}", text)
    if not text and not html:
        report.looks_meaningful = False
        report.readable = False
        report.notes += ("Kein Textkörper vorhanden",)
    elif len(words) < 3 and not html:
        report.looks_meaningful = False
        report.notes += ("Textkörper enthält kaum lesbare Wörter",)

    lowered = text.lower()
    report.lure_hits = tuple(sorted({p for p in _LURE_PHRASES if p in lowered})[:8])
    report.credential_hits = tuple(
        sorted({p for p in _CREDENTIAL_PHRASES if _phrase_trifft(p, lowered)})[:8]
    )

    # HTML vs. plain-text divergence: a mail with a rich HTML body but a
    # near-empty text part often hides its real content from text scanners.
    if html and text:
        plain_from_html = _strip_html(html)
        if plain_from_html:
            visible = len(plain_from_html)
            report.html_text_divergence = max(
                0.0, (visible - len(text)) / visible
            )
            if report.html_text_divergence > 0.5 and visible > 200:
                report.notes += (
                    (
                        (
                            "HTML-Inhalt deutlich umfangreicher als der Textteil "
                            f"({visible} vs. {len(text)} Zeichen)"
                        )
                    ),
                )

    # Hidden text: white-on-white, zero font size, or display:none.
    #
    # DIE EINE STELLE, die den HTML-Rumpf daraufhin prueft. `analyze_structure`
    # hatte dieselben drei Techniken noch einmal (MAIL_HTML_HIDDEN_TEXT,
    # MEDIUM/15) — eine Mail mit display:none bekam BEIDE Befunde, +20 Punkte,
    # mit fast gleichem Titel ("Versteckter Text im HTML-Teil" /
    # "Unsichtbarer Text im HTML-Teil"). Gemessen an
    # dist/Testdateien-EML/Phishing/phish_body.eml.
    #
    # Geblieben ist diese Regel mit ihrem kalibrierten Gewicht 5: versteckter
    # Text allein ist KEIN starker Beleg — Werbe-Mail versteckt dort ihren
    # Preheader. Mit 15 Punkten kippte jede gespeicherte Newsletter-Mail.
    if html:
        hidden_patterns = (
            r"color\s*:\s*#?fff(?:fff)?\b",
            r"color\s*:\s*white\b",
            r"font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|%)?\b",
            r"display\s*:\s*none\b",
            r"visibility\s*:\s*hidden\b",
            r"opacity\s*:\s*0(?:\.0+)?\s*[;\x22']",
            r"max-height\s*:\s*0\b",
            r"\bwidth\s*=\s*[\x22']?0[\x22']?",
        )
        if any(re.search(p, html, re.IGNORECASE) for p in hidden_patterns):
            report.hidden_text = True
            report.notes += ("Versteckter Text im HTML (weiß/0px/display:none)",)
        if _RX_TRACKING_PIXEL.search(html):
            report.tracking_pixel = True

    return report


# --------------------------------------------------------------------------- #
# Header / structure checks
# --------------------------------------------------------------------------- #


@dataclass
class StructureReport:
    """Outcome of the header and authentication checks."""

    findings: tuple[tuple[str, str], ...] = ()  # (kind, detail)


# Homoglyphs used to make a brand name look right while being a different
# string: a brand written with a CYRILLIC A never matches it byte-for-byte, and
# a plain substring check is blind to it. Folding to ASCII restores the
# comparison; the mixed-script check below then flags the trick itself.
_CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u04bb": "h",
    "\u0501": "d", "\u051b": "q", "\u0475": "v", "\u04bd": "e", "\u04cf": "l",
    "\u0391": "a", "\u0392": "b", "\u0395": "e", "\u0396": "z", "\u0397": "h",
    "\u0399": "i", "\u039a": "k", "\u039c": "m", "\u039d": "n", "\u039f": "o",
    "\u03a1": "p", "\u03a4": "t", "\u03a5": "y", "\u03a7": "x",
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
    "\uff0e": ".", "\u2024": ".", "\u3002": ".",
    # Invisible/zero-width characters: "Pay<ZWSP>pal" renders as "Paypal"
    # while breaking every exact comparison. Folded to nothing.
    "\u200b": "", "\u200c": "", "\u200d": "", "\u2060": "", "\ufeff": "",
    "\u00ad": "", "\u180e": "",
}


def _has_invisible_chars(text: str) -> bool:
    """True when text carries zero-width/soft-hyphen characters."""
    return any(
        ch in "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e" for ch in text
    )


def _fold_confusables(text: str) -> str:
    """Map lookalike Unicode characters to their ASCII equivalents."""
    if not text:
        return ""
    return "".join(_CONFUSABLES.get(ch, ch) for ch in text)


def _has_mixed_script(text: str) -> bool:
    """True when one word mixes Latin with Cyrillic/Greek letters.

    Legitimate mail does not mix scripts inside a single word; doing so is the
    standard way to make a brand name look authentic while breaking exact
    matching (IDN/homoglyph spoofing).
    """
    for word in text.split():
        has_latin = any("a" <= ch.lower() <= "z" for ch in word)
        has_cyr_or_greek = any(
            "\u0400" <= ch <= "\u04ff" or "\u0370" <= ch <= "\u03ff" for ch in word
        )
        if has_latin and has_cyr_or_greek:
            return True
    return False


def _domain_of(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().lower().strip(">")


def _registrable(domain: str) -> str:
    """Very small eTLD+1 approximation (enough to compare two senders).

    KLEIN GESCHRIEBEN, und das ist keine Kosmetik: Domains sind laut RFC 1035
    case-insensitiv. GEMESSEN feuerte MAIL_MESSAGE_ID_DOMAIN auf einer echten
    Mail, weil die Message-ID 'munnari.OZ.AU' sagte und der Absender
    'munnari.oz.au' — derselbe Name in verschiedener Schreibweise. Drei
    Geschwisterstellen schrieben den Aufruf bereits als
    ``_registrable(x.lower())``; hier steht es jetzt einmal, statt an jeder
    Aufrufstelle wiederholt zu werden.
    """
    if not domain:
        return ""
    domain = domain.lower()
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    # Handle the common two-label public suffixes seen in mail.
    two_label = {"co.uk", "org.uk", "ac.uk", "com.au", "co.nz", "com.br"}
    if ".".join(parts[-2:]) in two_label:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


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


def looks_like_mail(facts: MailFacts) -> bool:
    """Traegt diese Datei ueberhaupt Mail-Kopfzeilen?

    Gebraucht von der Anzeige: eine .eml, die keine ist (Binaermuell, ein
    umbenanntes PDF), darf NICHT als Mail dargestellt werden. Gemessen zeigte
    die Vorschau fuer eine Datei aus rohen Bytes "Textinhalt" mit Steuerzeichen
    — der Nutzer haette eine Anzeige gesehen, die eine Mail behauptet, die es
    nicht gibt.

    Geprueft wird auf Kopfzeilen, die jede echte Mail hat: Absender, Betreff,
    Datum oder Message-ID. Eine davon genuegt — manche generierte Mail hat
    keine Message-ID, und manche Weiterleitung keinen sauberen Absender.
    """
    if facts.parse_error:
        return False
    return bool(
        facts.from_addr
        or facts.subject.strip()
        or facts.message_id.strip()
        or facts.date_header.strip()
        or facts.to_addr
    )


def analyze_structure(facts: MailFacts) -> StructureReport:
    """Check whether the mail's headers hang together.

    All checks are heuristic and local: no DNS, no SPF/DKIM computation of our
    own (that needs the receiving server's context) — we only read what the
    mail already carries in ``Authentication-Results``.
    """
    findings: list[tuple[str, str]] = []

    # The header cap must never be silent: a truncated block means the
    # Received chain, Authentication-Results or a From header behind the cut
    # was not seen. The finding reaches the report through the structure
    # findings (eml_pipeline renders every entry), so the reader knows the
    # verdict is based on a prefix (audit SEC-034).
    if facts.header_truncated:
        findings.append(
            (
                "MAIL_HEADER_TRUNCATED",
                (
                    "Der Kopfzeilenblock ist größer als "
                    f"{_MAX_HEADER_BLOCK_BYTES} Bytes — nur der Anfang wurde "
                    "ausgewertet. Spätere Kopfzeilen (Received-Kette, "
                    "Authentication-Results, Absender) können fehlen."
                ),
            )
        )

    from_domain = _registrable(_domain_of(facts.from_addr))
    reply_domain = _registrable(_domain_of(facts.reply_to))
    return_domain = _registrable(_domain_of(facts.return_path))

    # Reply-To pointing at a different organisation is the classic BEC setup.
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(
            (
                "MAIL_REPLY_TO_MISMATCH",
                (
                    "Antworten gehen an eine andere Domain "
                    f"({facts.reply_to}) als der Absender ({facts.from_addr})"
                ),
            )
        )
    if return_domain and from_domain and return_domain != from_domain:
        # Auf einer Mailingliste ist die abweichende Rueckkehradresse der
        # NORMALZUSTAND: die Mail kommt von der Liste, ihr "-admin@" bzw.
        # "-bounces@" gehoert zur Liste, waehrend From den Autor nennt.
        # GEMESSEN: 4 von 20 echten Ham-Mails aus dem SpamAssassin-Korpus
        # waren ROT — drei davon an genau dieser Regel.
        findings.append(
            (
                "MAIL_RETURN_PATH_MISMATCH",
                (
                    "Bounce-Adresse "
                    f"({facts.return_path}) passt nicht zum Absender "
                    f"({facts.from_addr})"
                    + (_LISTEN_HINWEIS if facts.is_mailing_list else "")
                ),
            )
        )

    display_lower = _fold_confusables((facts.from_display or "").lower())
    # Mixed-script display name: writing a brand with lookalike letters from
    # another script defeats any exact comparison. Reported on its own —
    # it is a deliberate technique, not an accident.
    if _has_mixed_script(facts.from_display or "") or _has_invisible_chars(
        facts.from_display or ""
    ):
        findings.append(
            (
                "MAIL_DISPLAY_NAME_MIXED_SCRIPT",
                (
                    "Der Anzeigename enthält unsichtbare oder systemfremde "
                    f"Zeichen ({facts.from_display!r}) — typisch für "
                    "nachgebaute Markennamen mit ähnlich aussehenden Zeichen."
                ),
            )
        )
    # Display-name impersonation: a brand appears in the display name while
    # the actual sending domain is not the brand's. The brand must be a real
    # word in the domain — a mere substring match would treat the attacker's
    # own domain ("sparkasse-sicherheit.tk") as legitimate.
    if display_lower and from_domain:
        sender_site = _registrable(from_domain)
        for brand in _IMPERSONATED_BRANDS:
            if brand not in display_lower:
                continue
            brand_compact = brand.replace(" ", "").replace("-", "")
            # The sender may only claim the brand if the registrable domain
            # BELONGS to it (sparkasse.de) — a mere token match is exactly
            # what attackers exploit with "sparkasse-sicherheit.tk".
            owned_sites = {f"{brand_compact}.de", f"{brand_compact}.com",
                           f"{brand_compact}.net", f"{brand_compact}.org",
                           f"{brand_compact}.eu", f"{brand_compact}.at",
                           f"{brand_compact}.ch"}
            if sender_site not in owned_sites:
                findings.append(
                    (
                        "MAIL_DISPLAY_NAME_SPOOF",
                        (
                            f"Anzeigename nennt '{brand}', "
                            f"Absenderdomain ist aber '{from_domain}'"
                        ),
                    )
                )
                break

    # An address inside the DISPLAY NAME that is not the sender's own: the
    # classic "support@paypal.com <attacker@evil.tld>". The brand list above
    # only catches known brands; this catches the technique itself, whatever
    # the name claims.
    # Only when the brand check did NOT already fire: "support@paypal.com" as
    # the display name is ONE cause, and both branches reported it — 30 + 30
    # for the same sentence. The brand check is the more specific statement
    # (it names the impersonated brand), so it wins; this branch covers the
    # technique for names that no brand list knows.
    if facts.from_display and not any(k == "MAIL_DISPLAY_NAME_SPOOF" for k, _ in findings):
        # The quantifiers are BOUNDED on purpose. `[\w.+-]+@` without a limit is
        # quadratic on attacker-controlled input: `[\w.+-]+` starts at every
        # position and then runs to the end of the string looking for an '@'
        # that never comes. Measured with a 40 000-character display name of
        # "A": ONE findall call took 10.98 s, and 200 000 characters took 276 s
        # — a ReDoS in the same shape as _ANCHOR_RE in round 3. Real local
        # parts and domains are far below these bounds (RFC 5321: 64 / 255).
        for claimed in re.findall(
            ADDRESS_IN_DISPLAY_RE,
            facts.from_display,
            re.IGNORECASE,
        ):
            if from_domain and _registrable(claimed.lower()) != from_domain:
                findings.append(
                    (
                        "MAIL_DISPLAY_ADDR_MISMATCH",
                        (
                            f"Der Anzeigename nennt die Adresse "
                            f"'{claimed}', abgesendet wurde aber von "
                            f"'{facts.from_addr or from_domain}'"
                        ),
                    )
                )
                break

    # Lookalike sender domains (typosquatting of a brand).
    if from_domain:
        stripped = from_domain.replace("-", "").replace("0", "o").replace("1", "l")
        for brand in _IMPERSONATED_BRANDS:
            compact = brand.replace(" ", "").replace("-", "")
            if len(compact) < 5:
                continue
            if compact not in from_domain and compact in stripped:
                findings.append(
                    (
                        "MAIL_LOOKALIKE_DOMAIN",
                        (
                            f"Absenderdomain '{from_domain}' ähnelt "
                            f"der Marke '{brand}', ist aber nicht identisch"
                        ),
                    )
                )
                break

    # Authentication results recorded by the receiving server.
    verdicts = facts.auth_verdicts or auth_verdicts(facts.auth_results)
    failed = [mech.upper() for mech in _AUTH_MECHANISMS if verdicts.get(mech) == "fail"]
    if failed:
        # ONE finding, not one per mechanism. A mail whose SPF, DKIM and DMARC
        # all fail has ONE cause — the sender is not who it claims — and the
        # per-mechanism loop charged 3 x 15 = 45 for it, enough to push any
        # five-point signal over ANCHOR_CRITICAL_SCORE. The failed mechanisms
        # are named in the detail, where they belong.
        findings.append(
            (
                "MAIL_AUTH_FAIL",
                (
                    "Laut Authentication-Results fehlgeschlagen: "
                    + ", ".join(failed)
                ),
            )
        )

    # A file that CLAIMS full authentication while its sender is spoofed is
    # the combination that matters. Authentication-Results is written by the
    # receiving server — but in a file the user is analysing it is just bytes,
    # and the attacker writes them: measured, a forged
    # "spf=pass dkim=pass dmarc=pass" line silenced the "not authenticated"
    # note completely and was displayed as "SPF bestanden". A spoofing signal
    # next to a claimed pass is not two facts, it is one deception.
    claimed_pass = all(verdicts.get(m) == "pass" for m in _AUTH_MECHANISMS)
    spoof_signals = {
        "MAIL_DISPLAY_NAME_SPOOF",
        "MAIL_DISPLAY_ADDR_MISMATCH",
        "MAIL_REPLY_TO_MISMATCH",
        "MAIL_LOOKALIKE_DOMAIN",
    }
    if claimed_pass and any(k in spoof_signals for k, _ in findings):
        findings.append(
            (
                "MAIL_AUTH_CLAIMED_SPOOF",
                (
                    "Die Datei behauptet bestandene Authentifizierung "
                    "(SPF/DKIM/DMARC) und traegt gleichzeitig ein "
                    "Spoofing-Signal — die Kopfzeile stammt aus der Datei "
                    "selbst und ist nicht nachpruefbar"
                ),
            )
        )

    # The absence must be visible, not silent. A mail whose sender uses no
    # SPF/DKIM/DMARC at all is not the same as one that passed — and saying
    # nothing about it read like approval. "none" (header present, mechanism
    # not mentioned) is the same statement as "unknown" (no header): about this
    # mechanism nothing is known.
    #
    # A mechanism that FAILED is not absent — it is present and negative, and
    # MAIL_AUTH_FAIL already says so. Counting it here reported the same
    # mechanism twice with opposite wording.
    unauthenticated = [
        mech.upper()
        for mech in _AUTH_MECHANISMS
        if verdicts.get(mech) in ("none", "unknown")
    ]
    if unauthenticated:
        if facts.received_count == 0:
            # Same cause as MAIL_NO_RECEIVED — a generated file never met a
            # mail server, so there is nothing to authenticate. Reported as a
            # diagnosis; the weighted statement is the Received note.
            findings.append(
                (
                    "MAIL_AUTH_UNVERIFIABLE",
                    (
                        "Keine Authentifizierung beurteilbar ("
                        + ", ".join(unauthenticated)
                        + ") — die Mail lief nicht über einen Mailserver"
                    ),
                )
            )
        else:
            findings.append(
                (
                    "MAIL_AUTH_ABSENT",
                    (
                        "Kein Nachweis der Absenderauthentifizierung für "
                        + ", ".join(unauthenticated)
                        + " — der Absender nutzt diese Verfahren nicht oder "
                        "der empfangende Server hat sie nicht geprüft"
                    ),
                )
            )

    # A mail with no Received header at all never passed a mail server.
    if facts.received_count == 0:
        findings.append(
            (
                "MAIL_NO_RECEIVED",
                (
                    "Keine Received-Kette vorhanden — die Mail lief nicht "
                    "über einen Mailserver (typisch für generierte Dateien)"
                ),
            )
        )

    # A missing Message-ID is unusual for real mail.
    if not facts.message_id.strip():
        findings.append(
            ("MAIL_NO_MESSAGE_ID", "Kein Message-ID-Header vorhanden")
        )

    # ------------------------------------------------------------------ #
    # Behauptungen gegen die Received-Kette pruefen.
    #
    # Alles in einer Mail ist angreiferkontrolliert. Eine Datei, die nie durch
    # ein Gateway lief, kann "Authentication-Results: mx.microsoft.com;
    # spf=pass" selbst hineinschreiben. Die Kette ist die einzige Angabe, die
    # der Faelscher mitschreiben muss, wenn die Mail echt aussehen soll — und
    # genau daran laesst sich die Behauptung messen.
    # ------------------------------------------------------------------ #
    chain_names = {
        name.lower()
        for hop in facts.received_hops
        for name in (hop.from_host, hop.by_host)
        if name
    }

    # Nur echte FQDNs pruefen. Ein Name ohne Punkt ("mx") ist kein
    # Servername, den man gegen die Kette halten koennte — die Fixtures in
    # tests/ nutzen genau solche Platzhalter, und ein Befund darauf waere
    # Rauschen. Echte Authentication-Results nennen immer einen FQDN.
    if facts.auth_claimed_by and "." in facts.auth_claimed_by and chain_names:
        claimed = facts.auth_claimed_by.lower()
        # Suffix-Vergleich: "mx.firma.de" und "mx.firma.de (Postfix)" sind
        # dieselbe Station, "mail.firma.de" und "firma.de" auch.
        backed = any(
            claimed == name
            or claimed.endswith("." + name)
            or name.endswith("." + claimed)
            for name in chain_names
        )
        if not backed:
            findings.append(
                (
                    "MAIL_AUTH_CLAIM_UNBACKED",
                    (
                        f"Die Kopfzeile behauptet bestandene Authentifizierung "
                        f"durch '{facts.auth_claimed_by}', dieser Server kommt "
                        f"in der Received-Kette aber nicht vor — die Kopfzeile "
                        f"stammt aus der Datei selbst und ist nicht gedeckt"
                    ),
                )
            )

    # Die letzte Station der Kette ist die, mit der sich der Absender
    # verbunden hat. Eine private oder reservierte IP dort heisst: die Mail
    # behauptet, aus einem internen Netz zu kommen, das sie nie beruehrt hat.
    if facts.received_hops:
        first_ip = facts.received_hops[-1].ip
        if first_ip and _is_private_ip(first_ip):
            findings.append(
                (
                    "MAIL_RECEIVED_PRIVATE_IP",
                    (
                        f"Die Absender-Station der Received-Kette nennt die "
                        f"private IP {first_ip} — eine Mail von aussen kann "
                        f"nicht von einer internen Adresse stammen"
                    ),
                )
            )

    # DMARC-Alignment SELBST rechnen, statt es zu lesen. DMARC verlangt, dass
    # die From-Domain mit der SPF-Domain (Envelope = Return-Path) oder der
    # DKIM-Domain (d=) uebereinstimmt — "relaxed" vergleicht die registrierbare
    # Domain, "strict" die volle. Beides ist OHNE DNS entscheidbar; nur die
    # Policy (p=) braucht einen Abruf und bleibt deshalb aussen vor.
    if facts.from_addr and (facts.return_path or facts.dkim_domain):
        from_domain = _registrable(_domain_of(facts.from_addr))
        spf_domain = _registrable(_domain_of(facts.return_path)) if facts.return_path else ""
        dkim_domain = _registrable(facts.dkim_domain.lower()) if facts.dkim_domain else ""
        spf_aligned = bool(spf_domain) and spf_domain == from_domain
        dkim_aligned = bool(dkim_domain) and dkim_domain == from_domain
        if from_domain and not spf_aligned and not dkim_aligned:
            # Listen versenden die Mail NEU und setzen dabei ihre eigene
            # Envelope-Domain. Dass die Ausrichtung dann nicht greift, ist
            # kein Faelschungshinweis, sondern die Bauart (deshalb schreiben
            # viele Listen die From-Adresse um).
            findings.append(
                (
                    "MAIL_DMARC_ALIGNMENT_FAIL",
                    (
                        f"Kein DMARC-Alignment: der Absender nennt "
                        f"'{_domain_of(facts.from_addr)}'"
                        + (
                            f", die Envelope-Domain ist "
                            f"'{_domain_of(facts.return_path)}'"
                            if facts.return_path
                            else ""
                        )
                        + (
                            f", die DKIM-Domain ist '{facts.dkim_domain}'"
                            if facts.dkim_domain
                            else ""
                        )
                        + " — beide weichen ab, damit greift keine "
                        "DMARC-Pruefung"
                    ),
                )
            )

    # Behauptungen fremder Filter: anzeigen, aber als Behauptung. Steht der
    # Server, der sie ausgestellt haben will, nicht in der Kette, ist die
    # Zeile mitgeschrieben worden.
    # Der Befund braucht einen WIDERSPRUCH, sonst feuert er auf jeder echten
    # Mail mit Gateway: X-Spam-Status steht in praktisch jeder gefilterten
    # Mail, und "ist eine Behauptung" allein ist kein Befund — angezeigt wird
    # sie ohnehin in der Vorschau. Gemeldet wird, wenn die Behauptung nicht
    # sein KANN: nennt die Kopfzeile einen Server, der nicht in der Kette
    # steht, oder gibt es ueberhaupt keine Kette (eine Datei, die nie einen
    # Server gesehen hat, kann kein Filterurteil tragen).
    for header, value in facts.filter_claims.items():
        named = _RX_FILTER_SERVER.search(value)
        if named:
            name = named.group(1).lower()
            backed = any(
                name == chain or name.endswith("." + chain) or chain.endswith("." + name)
                for chain in chain_names
            )
            if backed:
                continue
            grund = f"der genannte Server '{named.group(1)}' fehlt in der Kette"
        elif facts.received_hops:
            continue  # kein Server genannt, Kette vorhanden: plausibel
        else:
            grund = "die Mail hat keine Received-Kette"
        findings.append(
            (
                "MAIL_FILTER_CLAIM",
                (
                    f"{header} behauptet ein Urteil eines fremden Filters "
                    f"({value[:120]}) — {grund}, die Kopfzeile stammt aus der "
                    f"Datei selbst"
                ),
            )
        )

    # Zeitversatz: der Date-Kopf stammt vom Absender, der Zeitstempel der
    # ersten Zustellung von der Gegenstelle. Beide sind faelschbar, aber sie
    # muessen zueinander passen — eine Mail, die Stunden "unterwegs" war,
    # oder ein nachtraeglich gesetzter Date-Kopf faellt hier auf.
    if facts.date_header and facts.received_hops:
        sent = _parse_mail_date(facts.date_header)
        delivered = _parse_mail_date(facts.received_hops[0].stamp)
        if sent and delivered:
            gap = abs((delivered - sent).total_seconds())
            if gap > _MAX_DELIVERY_GAP_SECONDS:
                findings.append(
                    (
                        "MAIL_RECEIVED_TIME_ANOMALY",
                        (
                            f"Zwischen dem Date-Kopf und der ersten Zustellung "
                            f"liegen {gap / 3600:.1f} Stunden — der Zeitstempel "
                            f"passt nicht zum Versand"
                        ),
                    )
                )

    # Eine TLS-Angabe in der Kette ist eine Behauptung der Gegenstelle. Eine
    # veraltete Version wird berichtet, aber NICHT als Schwachstelle gewertet:
    # wir haben die Verbindung nicht gesehen.
    for hop in facts.received_hops:
        if hop.tls and hop.tls.lower() in _WEAK_TLS:
            findings.append(
                (
                    "MAIL_RECEIVED_WEAK_TLS",
                    (
                        f"Die Received-Kette behauptet '{hop.tls}' — eine "
                        f"veraltete Transportverschluesselung. Die Angabe "
                        f"stammt aus der Datei und ist nicht nachpruefbar"
                    ),
                )
            )
            break

    # Message-ID: Format und Sende-Domain. Die ID soll eine Domain tragen, die
    # zum Absender passt; eine fremde oder fehlende Domain ist ein Hinweis auf
    # eine generierte Datei.
    if facts.message_id.strip():
        id_domain = _message_id_domain(facts.message_id)
        from_domain = _registrable(_domain_of(facts.from_addr)) if facts.from_addr else ""
        if not id_domain:
            findings.append(
                (
                    "MAIL_MESSAGE_ID_ODD",
                    (
                        f"Die Message-ID '{facts.message_id[:80]}' traegt keine "
                        f"Domain — das Format passt nicht zu einer echten Mail"
                    ),
                )
            )
        elif from_domain and _registrable(id_domain) != from_domain:
            findings.append(
                (
                    "MAIL_MESSAGE_ID_DOMAIN",
                    (
                        f"Die Message-ID stammt von '{id_domain}', der Absender "
                        f"nennt '{_domain_of(facts.from_addr)}'"
                    ),
                )
            )

    # Absender-Domain gegen die lokale Phishing-Blockliste. Die URL-Liste
    # erkennt EINEN bekannten Link; diese erkennt den ABSENDER — eine
    # Phishing-Mail mit wechselnden Pfaden wird sonst nur zufaellig gefunden.
    # Rein lokal, kein Netzzugriff (core/domain_blocklist).
    if facts.from_addr or facts.return_path:
        gelistet, domain_error = load_domain_blocklist_or_error()
        if domain_error:
            findings.append(
                (
                    "DOMAIN_BLOCKLIST_UNAVAILABLE",
                    (
                        "Die lokale Phishing-Domain-Blockliste konnte nicht gelesen "
                        "werden; der Absender-Abgleich ist unvollständig."
                    ),
                )
            )
        for label, wert in (
            ("Absender", _domain_of(facts.from_addr)),
            ("Bounce-Adresse", _domain_of(facts.return_path)),
        ):
            if wert and is_blocked_domain(wert, gelistet):
                findings.append(
                    (
                        "MAIL_SENDER_DOMAIN_BLOCKED",
                        (
                            f"Die {label}-Domain '{wert}' steht auf der Liste "
                            f"bekannter Phishing-Domains — von dort kommt "
                            f"keine echte Rechnung"
                        ),
                    )
                )
                break

    # Absender-IP gegen die lokale Netz-Blockliste (Spamhaus DROP: Bulletproof-
    # Hosting, Botnetze). Geprueft wird die ERSTE Station der Kette — die
    # Adresse, mit der sich der Absender verbunden hat. Rein lokal.
    if facts.received_hops:
        absender_ip = facts.received_hops[-1].ip
        if absender_ip:
            netze, ip_error = load_ip_blocklist_or_error(config.IP_BLOCKLIST_FILE)
            if ip_error:
                findings.append(
                    (
                        "IP_BLOCKLIST_UNAVAILABLE",
                        (
                            "Die lokale IP-Blockliste konnte nicht gelesen werden; "
                            "der Absender-IP-Abgleich ist unvollständig."
                        ),
                    )
                )
            if netze and is_blocked_ip(absender_ip, netze):
                findings.append(
                    (
                        "MAIL_SENDER_IP_BLOCKED",
                        (
                            f"Die Absender-IP {absender_ip} liegt in einem Netz "
                            f"bekannter Spam- und Angriffsquellen"
                        ),
                    )
                )

    # DKIM: die signierende Domain gegen die Absenderdomain stellen. Das ist
    # OHNE Netz entscheidbar und sagt, ob die Signatur ueberhaupt zum Absender
    # gehoert. Die Signatur selbst ist damit NICHT geprueft.
    if facts.dkim_domain and facts.from_addr:
        signer = _registrable(facts.dkim_domain.lower())
        sender = _registrable(_domain_of(facts.from_addr))
        if signer and sender and signer != sender:
            findings.append(
                (
                    "MAIL_DKIM_DOMAIN_MISMATCH",
                    (
                        f"Die DKIM-Signatur stammt von '{facts.dkim_domain}', "
                        f"der Absender nennt '{_domain_of(facts.from_addr)}' — "
                        f"die Signatur deckt eine andere Domain"
                    ),
                )
            )

    return StructureReport(findings=tuple(findings))


# --------------------------------------------------------------------------- #
# Attachment names (the files themselves are scanned by the dispatcher)
# --------------------------------------------------------------------------- #


def _clean_attachment_name(name: str) -> str:
    """Normalise a display filename for the risk checks.

    Two tricks hide the real type from the *user* while leaving the raw
    string parseable here:

    * **NUL byte** — ``rechnung.pdf.exe\\x00.txt``: a mail client shows only
      the part before the NUL (``rechnung.pdf.exe``), so the trailing ".txt"
      looks harmless.
    * **Bidi override** (U+202E and friends) — ``rechnung.pdf\\u202eexe`` is
      *rendered* as ``rechnung.pdf`` while the file is really an executable.
      This is the classic "RLO trick" and a genuine deception.

    Both are normalised away before the suffix checks run.
    """
    if not name:
        return ""
    # Drop control characters (incl. NUL) and bidi overrides/isolates.
    cleaned = "".join(
        ch
        for ch in name
        if ch not in "\x00" and not ("\u202a" <= ch <= "\u202e") and not ("\u2066" <= ch <= "\u2069")
    )
    return cleaned.strip()


def risky_attachment_names(names: list[str]) -> tuple[tuple[str, str], ...]:
    """Flag attachment names dangerous to open or designed to hide their type.

    EVERY name is checked. The old ``names[:20]`` made the check evadable with
    20 harmless attachments in front of ``rechnung.pdf.exe``: the executable
    then carried no finding at all (audit BUG-068). The caller's part walk is
    already bounded (``_MAX_HEADER_LINES * 4`` in :func:`parse_mail`), so this
    list cannot grow without that budget.
    """
    out: list[tuple[str, str]] = []
    for raw in names:
        name = (raw or "").strip()
        if not name:
            continue
        # A deception attempt is itself worth reporting, even when the cleaned
        # name turns out harmless.
        if any(ch == "\x00" or "\u202a" <= ch <= "\u202e" or "\u2066" <= ch <= "\u2069" for ch in name):
            out.append(
                (
                    "MAIL_ATTACH_NAME_TRICK",
                    (
                        "Anhangsname enthält unsichtbare Steuerzeichen "
                        f"(angezeigter Typ kann täuschen): {name!r}"
                    ),
                )
            )
        cleaned = _clean_attachment_name(name)
        lowered = cleaned.lower()
        if _DOUBLE_EXT_RE.search(lowered):
            out.append(
                (
                    "MAIL_ATTACH_DOUBLE_EXT",
                    f"Dateiname tarnt den echten Typ: {cleaned}",
                )
            )
        elif lowered.endswith(_RISKY_ATTACHMENT_SUFFIXES):
            out.append(
                (
                    "MAIL_ATTACH_RISKY_TYPE",
                    f"Direkt ausführbarer/aktiver Anhangtyp: {cleaned}",
                )
            )
    return tuple(out)


# --------------------------------------------------------------------------- #
# Link reputation (opt-in, hash-based — see core/url_reputation.py)
# --------------------------------------------------------------------------- #


def summarize_links(links: list[LinkFacts]) -> tuple[tuple[str, str], ...]:
    """Static link findings; the opt-in reputation lookup runs separately."""
    mismatches = [link for link in links if link.mismatch]
    ip_links = [link for link in links if link.is_ip_literal]
    shorteners = [link for link in links if link.is_shortener]
    punycode = [link for link in links if link.is_punycode]
    risky = [link for link in links if link.risky_tld]
    creds = [link for link in links if link.has_credentials]
    dangerous = [link for link in links if link.scheme in _DANGEROUS_URI_SCHEMES]

    out: list[tuple[str, str]] = []
    if dangerous:
        detail = ", ".join(sorted({link.scheme for link in dangerous}))
        out.append(
            (
                "MAIL_LINK_DANGEROUS_SCHEME",
                "Link nutzt ein gefährliches Schema (führt Code aus bzw. "
                "greift auf lokale Dateien zu): " + detail,
            )
        )
    if mismatches:
        detail = "; ".join(
            f"{link.display_text} → {link.host}" for link in mismatches[:3]
        )
        out.append(
            (
                "MAIL_LINK_TEXT_MISMATCH",
                "Linktext zeigt auf eine andere Adresse als das Ziel: " + detail,
            )
        )
    if ip_links:
        detail = ", ".join(link.url for link in ip_links[:3])
        out.append(
            (
                "MAIL_LINK_IP_LITERAL",
                "Link zeigt direkt auf eine IP-Adresse (keine Domain): " + detail,
            )
        )
    if shorteners:
        detail = ", ".join(link.host for link in shorteners[:3])
        out.append(
            (
                "MAIL_LINK_SHORTENER",
                "Link nutzt einen Kurzdienst (Ziel verschleiert): " + detail,
            )
        )
    if punycode:
        detail = ", ".join(link.host for link in punycode[:3])
        out.append(
            (
                "MAIL_LINK_PUNYCODE",
                "Link nutzt Punycode (mögliche Zeichen-Verwechslung): " + detail,
            )
        )
    if risky:
        detail = ", ".join(link.host for link in risky[:3])
        out.append(
            (
                "MAIL_LINK_RISKY_TLD",
                "Link endet auf einer häufig missbrauchten Top-Level-Domain: "
                + detail,
            )
        )
    if creds:
        detail = ", ".join(link.url for link in creds[:2])
        out.append(
            (
                "MAIL_LINK_CREDENTIALS",
                "Link enthält Zugangsdaten (user@host) — verschleiert das Ziel: "
                + detail,
            )
        )
    return tuple(out)
