"""Static analysis of parsed emails: body heuristics, structure, and links.

MIME, header, address, Received-chain, and link extraction live in
:mod:`malaz.core.eml_parser`; all public symbols and tested compatibility
seams are re-exported here via explicit PEP-484 aliases.

Everything here is strictly local and offline (no DNS, no network, no
execution of HTML/JS).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .. import config as config
from .domain_blocklist import is_blocked_domain, load_domain_blocklist_or_error
from .eml_parser import (
    _AUTH_MECHANISMS as _AUTH_MECHANISMS,
)
from .eml_parser import (
    _DANGEROUS_URI_SCHEMES as _DANGEROUS_URI_SCHEMES,
)
from .eml_parser import (
    _MAX_HEADER_BLOCK_BYTES as _MAX_HEADER_BLOCK_BYTES,
)
from .eml_parser import (
    _MAX_LINKS as _MAX_LINKS,
)
from .eml_parser import (
    LinkFacts as LinkFacts,
)
from .eml_parser import (
    MailFacts as MailFacts,
)
from .eml_parser import (
    ReceivedHop as ReceivedHop,
)
from .eml_parser import (
    _has_risky_tld as _has_risky_tld,
)
from .eml_parser import (
    _is_ip_literal as _is_ip_literal,
)
from .eml_parser import (
    _parse_received as _parse_received,
)
from .eml_parser import (
    _split_address as _split_address,
)
from .eml_parser import (
    _strip_html as _strip_html,
)
from .eml_parser import (
    _strip_www as _strip_www,
)
from .eml_parser import (
    _unescape_entities as _unescape_entities,
)
from .eml_parser import (
    auth_verdicts as auth_verdicts,
)
from .eml_parser import (
    extract_links as extract_links,
)
from .eml_parser import (
    parse_mail as parse_mail,
)
from .eml_parser import (
    parse_received_chain as parse_received_chain,
)
from .ipblocklist import is_blocked_ip, load_ip_blocklist_or_error
from .risky_types import RISKY_SUFFIXES

# Well-known brands that phishing kits impersonate in the display name.
_IMPERSONATED_BRANDS = (
    "microsoft", "windows", "office365", "outlook", "apple", "icloud", "paypal",
    "amazon", "dhl", "dpd", "hermes", "fedex", "ups", "post", "sparkasse",
    "volksbank", "commerzbank", "deutsche bank", "ing-diba",
    "netflix", "spotify", "telekom", "vodafone", "1&1", "rewe", "lidl", "aldi",
    "google", "facebook", "instagram", "whatsapp", "binance", "coinbase",
)


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

# Ein Servername in einer Filterkopfzeile ("by mx.firma.de at ...").
_RX_FILTER_SERVER = re.compile(
    r"\b(?:by|at|from)\s+([\w.-]{1,255}\.[a-z]{2,})", re.IGNORECASE
)


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
